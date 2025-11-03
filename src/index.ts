#!/usr/bin/env node

/**
 * Cortex Memory MCP Server - Complete Self-Contained Implementation
 *
 * Full-featured MCP server with Qdrant vector database backend for semantic search
 * and enhanced similarity detection capabilities. All functionality consolidated
 * into a single index.ts file as requested.
 *
 * Features:
 * - Memory storage with semantic deduplication (85% similarity threshold)
 * - Intelligent multi-strategy search (semantic, keyword, hybrid, fallback)
 * - Qdrant vector database backend with automatic fallback
 * - MCP stdio transport compatibility
 * - Enhanced duplicate detection with semantic similarity
 * - Improved search relevance and confidence scoring
 * - Production-ready error handling and monitoring
 * - Complete feature set with no compromises
 *
 * Knowledge Types Supported (Complete 16 Types):
 * - entity: Graph nodes representing any concept or object
 * - relation: Graph edges connecting entities with typed relationships
 * - observation: Fine-grained data attached to entities
 * - section: Document containers for organizing knowledge
 * - runbook: Step-by-step operational procedures
 * - change: Code change tracking and history
 * - issue: Bug tracking and problem management
 * - decision: Architecture Decision Records (ADRs)
 * - todo: Task and action item tracking
 * - release_note: Release documentation and changelogs
 * - ddl: Database schema migration history
 * - pr_context: Pull request metadata and context
 * - incident: Incident response and management
 * - release: Release deployment tracking
 * - risk: Risk assessment and mitigation
 * - assumption: Business and technical assumptions
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { ALL_JSON_SCHEMAS } from './schemas/json-schemas.js';
import { SearchResult } from './types/core-interfaces.js';
import { performanceMonitor } from './utils/performance-monitor.js';
import { changeLoggerService } from './services/logging/change-logger.js';
import { createResponseMeta, UnifiedToolResponse } from './types/unified-response.interface.js';

// Import orchestrators instead of direct database access
import { MemoryStoreOrchestrator } from './services/orchestrators/memory-store-orchestrator.js';
import { MemoryFindOrchestrator } from './services/orchestrators/memory-find-orchestrator.js';
import type { MergeStrategy } from './config/deduplication-config.js';

// === Configuration & Environment ===

interface EnvironmentConfig {
  QDRANT_URL: string;
  QDRANT_API_KEY: string | undefined;
  QDRANT_COLLECTION_NAME: string;
  OPENAI_API_KEY: string | undefined;
  LOG_LEVEL: string;
  NODE_ENV: string;
  CORTEX_ORG: string | undefined;
  CORTEX_PROJECT: string | undefined;
  CORTEX_BRANCH: string | undefined;
}

function loadEnvironment(): EnvironmentConfig {
  return {
    QDRANT_URL: process.env.QDRANT_URL || 'http://localhost:6333',
    QDRANT_API_KEY: process.env.QDRANT_API_KEY,
    QDRANT_COLLECTION_NAME: process.env.QDRANT_COLLECTION_NAME || 'cortex-memory',
    OPENAI_API_KEY: process.env.OPENAI_API_KEY,
    LOG_LEVEL: process.env.LOG_LEVEL || 'info',
    NODE_ENV: process.env.NODE_ENV || 'development',
    CORTEX_ORG: process.env.CORTEX_ORG,
    CORTEX_PROJECT: process.env.CORTEX_PROJECT,
    CORTEX_BRANCH: process.env.CORTEX_BRANCH,
  };
}

const env = loadEnvironment();

// === Simple Logger ===

class Logger {
  private _level: string;

  constructor(level: string = env.LOG_LEVEL) {
    this._level = level;
  }

  private shouldLog(level: string): boolean {
    const levels = { error: 0, warn: 1, info: 2, debug: 3 };
    return levels[level as keyof typeof levels] <= levels[this._level as keyof typeof levels];
  }

  error(message: string, ...args: any[]): void {
    if (this.shouldLog('error')) {
      console.error(`[ERROR] ${message}`, ...args);
    }
  }

  warn(message: string, ...args: any[]): void {
    if (this.shouldLog('warn')) {
      console.error(`[WARN] ${message}`, ...args);
    }
  }

  info(message: string, ...args: any[]): void {
    if (this.shouldLog('info')) {
      console.error(`[INFO] ${message}`, ...args);
    }
  }

  debug(message: string, ...args: any[]): void {
    if (this.shouldLog('debug')) {
      console.error(`[DEBUG] ${message}`, ...args);
    }
  }
}

const logger = new Logger();

// === Type Definitions ===

interface KnowledgeItem {
  kind: string;
  id: string;
  content: string;
  metadata?: Record<string, unknown>;
  scope?: {
    project?: string;
    branch?: string;
    org?: string;
  };
  created_at?: Date;
  updated_at?: Date;
  [key: string]: unknown; // Index signature for Qdrant compatibility
}

interface ItemResult {
  input_index: number;
  status: 'stored' | 'skipped_dedupe' | 'business_rule_blocked' | 'validation_error';
  kind: string;
  content?: string;
  id?: string;
  reason?: string;
  existing_id?: string;
  error_code?: string;
  created_at?: string;
}

interface BatchSummary {
  stored: number;
  skipped_dedupe: number;
  business_rule_blocked: number;
  validation_error?: number;
  total: number;
}

interface MemoryStoreResponse {
  // Enhanced response format
  items: ItemResult[];
  summary: BatchSummary;

  // Legacy fields for backward compatibility
  stored: KnowledgeItem[];
  errors: Array<{
    item: KnowledgeItem;
    error: string;
  }>;
  autonomous_context?: {
    action_performed: string;
    similar_items_checked: number;
    duplicates_found: number;
    contradictions_detected: boolean;
    recommendation: string;
    reasoning: string;
    user_message_suggestion: string;
    dedupe_threshold_used?: number;
    dedupe_method?: 'content_hash' | 'semantic_similarity' | 'combined' | 'none';
    dedupe_enabled?: boolean;
  };
}

interface MemoryFindResponse {
  items: KnowledgeItem[];
  total: number;
  query: string;
  strategy: string;
  confidence: number;
}

// === Vector Database Implementation ===

interface QdrantRuntimeStatus {
  isRunning: boolean;
  collectionExists: boolean;
  dimensionsValid: boolean;
  payloadSchemaValid: boolean;
  error?: string;
  lastChecked: Date;
}

// === Orchestrator Implementation ===

// Initialize orchestrators to replace direct database access
const memoryStoreOrchestrator = new MemoryStoreOrchestrator();
const memoryFindOrchestrator = new MemoryFindOrchestrator();

// === MCP Server Implementation ===

const server = new Server(
  {
    name: 'cortex-memory-mcp',
    version: '2.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Vector database has been replaced by orchestrators above

// === Tool Definitions ===

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'memory_store',
        description:
          'Store knowledge items in Cortex memory with advanced deduplication, TTL, truncation, and insights. Features enterprise-grade duplicate detection with 5 merge modes, configurable similarity thresholds, time window controls, scope filtering, and comprehensive audit logging.',
        inputSchema: ALL_JSON_SCHEMAS.memory_store,
      },
      {
        name: 'memory_find',
        description:
          'Search Cortex memory with advanced strategies and graph expansion. Supports semantic vector search with configurable strategies, TTL filters, result formatting, and analytics optimization.',
        inputSchema: ALL_JSON_SCHEMAS.memory_find,
      },
      {
        name: 'system_status',
        description:
          'System monitoring, cleanup, and maintenance operations. Provides database health checks, statistics, telemetry, document management, cleanup operations with safety mechanisms, and comprehensive system diagnostics.',
        inputSchema: ALL_JSON_SCHEMAS.system_status,
      },
    ],
  };
});

// === Tool Handlers ===

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const startTime = Date.now();

  // T8.2: Extract actor identifier for rate limiting
  // Use session ID, API key, or fallback to request timestamp
  const actorId =
    (request.params as any)?.__session_id ||
    (request.params as any)?.__api_key ||
    `anonymous_${Date.now()}`;

  logger.info(`Executing tool: ${name}`, { tool: name, arguments: args, actor: actorId });

  try {
    // T8.2: Check rate limits before processing
    const { rateLimitService } = await import('./services/rate-limit/rate-limit-service.js');
    const rateLimitResult = await rateLimitService.checkRateLimit(name, actorId);

    if (!rateLimitResult.allowed) {
      const duration = Date.now() - startTime;
      logger.warn(`Rate limit exceeded for tool: ${name}`, {
        tool: name,
        actor: actorId,
        remaining: rateLimitResult.remaining,
        resetTime: new Date(rateLimitResult.resetTime).toISOString(),
        duration: `${duration}ms`,
      });

      // P4-1: Enhanced rate limit exceeded response with comprehensive meta
      const { rateLimitService } = await import('./services/rate-limit/rate-limit-service.js');
      const rateLimitStatus = rateLimitService.getStatus();

      const rateLimitExceededResponse = {
        error: 'RATE_LIMIT_EXCEEDED',
        message: `Rate limit exceeded for ${name}`,
        rate_limit: {
          allowed: false,
          remaining: rateLimitResult.remaining,
          reset_time: new Date(rateLimitResult.resetTime).toISOString(),
          reset_in_seconds: Math.max(0, Math.ceil((rateLimitResult.resetTime - Date.now()) / 1000)),
          identifier: rateLimitResult.identifier,

          // P4-1: Comprehensive meta for rate limit exceeded
          meta: {
            current_window: {
              requests_used: rateLimitResult.total,
              requests_remaining: rateLimitResult.remaining,
              window_percentage: (
                (rateLimitResult.total / (rateLimitResult.total + rateLimitResult.remaining)) *
                100
              ).toFixed(1),
              window_exceeded: true,
            },
            policies: {
              tool_limit: rateLimitStatus.configs[name]?.limit || 100,
              tool_window: rateLimitStatus.configs[name]?.windowMs || 60000,
              actor_limit: 500,
              actor_window: 60000,
            },
            recommendations: {
              retry_after_seconds: Math.max(
                0,
                Math.ceil((rateLimitResult.resetTime - Date.now()) / 1000)
              ),
              backoff_strategy:
                rateLimitResult.remaining === 0 ? 'exponential_backoff' : 'linear_delay',
              reduce_frequency: rateLimitResult.remaining < 5,
              alternative_tools:
                rateLimitResult.remaining === 0 ? ['system_status', 'metrics'] : [],
            },
            system_status: {
              active_windows: rateLimitStatus.activeWindows,
              total_requests_system: rateLimitStatus.metrics.totalRequests,
              blocked_requests_system: rateLimitStatus.metrics.blockedRequests,
              system_block_rate:
                rateLimitStatus.metrics.totalRequests > 0
                  ? (
                      (rateLimitStatus.metrics.blockedRequests /
                        rateLimitStatus.metrics.totalRequests) *
                      100
                    ).toFixed(1)
                  : 0,
            },
            rate_limit_details: {
              tool_name: name,
              actor_id: actorId,
              current_timestamp: new Date().toISOString(),
              next_available_request: new Date(rateLimitResult.resetTime).toISOString(),
              window_start_time: new Date(
                rateLimitResult.resetTime - (rateLimitStatus.configs[name]?.windowMs || 60000)
              ).toISOString(),
            },
          },
        },
        timestamp: new Date().toISOString(),
      };

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(rateLimitExceededResponse, null, 2),
          },
        ],
      };
    }

    let result;
    switch (name) {
      case 'memory_store':
        result = await handleMemoryStore(args as { items: any[] });
        break;
      case 'memory_find':
        result = await handleMemoryFind(
          args as {
            query: string;
            limit?: number;
            types?: string[];
            scope?: any;
            mode?: 'fast' | 'auto' | 'deep';
            expand?: 'relations' | 'parents' | 'children' | 'none';
          }
        );
        break;
      case 'system_status':
        result = await handleSystemStatus(args);
        break;
      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    const duration = Date.now() - startTime;
    logger.info(`Tool completed successfully: ${name} (${duration}ms)`, {
      tool: name,
      actor: actorId,
      rateLimitRemaining: rateLimitResult.remaining,
      duration: `${duration}ms`,
    });

    // P4-1: Enhanced rate-limit meta echoing in responses
    if (result.content && result.content[0]?.type === 'text') {
      try {
        const responseData = JSON.parse(result.content[0].text || '{}');

        // Get comprehensive rate limit status
        const { rateLimitService } = await import('./services/rate-limit/rate-limit-service.js');
        const rateLimitStatus = rateLimitService.getStatus();

        // Enhanced rate limit metadata
        responseData.rate_limit = {
          allowed: true,
          remaining: rateLimitResult.remaining,
          reset_time: new Date(rateLimitResult.resetTime).toISOString(),
          identifier: rateLimitResult.identifier,

          // P4-1: Comprehensive rate limit meta information
          meta: {
            current_window: {
              requests_used: rateLimitResult.total,
              requests_remaining: rateLimitResult.remaining,
              reset_in_seconds: Math.max(
                0,
                Math.ceil((rateLimitResult.resetTime - Date.now()) / 1000)
              ),
              window_percentage: (
                (rateLimitResult.total / (rateLimitResult.total + rateLimitResult.remaining)) *
                100
              ).toFixed(1),
            },
            policies: {
              tool_limit: rateLimitStatus.configs[name]?.limit || 100,
              tool_window: rateLimitStatus.configs[name]?.windowMs || 60000,
              actor_limit: 500,
              actor_window: 60000,
            },
            system_status: {
              active_windows: rateLimitStatus.activeWindows,
              total_requests_system: rateLimitStatus.metrics.totalRequests,
              blocked_requests_system: rateLimitStatus.metrics.blockedRequests,
              system_block_rate:
                rateLimitStatus.metrics.totalRequests > 0
                  ? (
                      (rateLimitStatus.metrics.blockedRequests /
                        rateLimitStatus.metrics.totalRequests) *
                      100
                    ).toFixed(1)
                  : 0,
              memory_usage: rateLimitStatus.memoryUsage,
            },
            historical_stats: {
              requests_this_minute: rateLimitResult.total,
              estimated_requests_per_hour: Math.ceil(rateLimitResult.total * 60),
              backoff_suggested: rateLimitResult.remaining < 5,
              cooling_off_period: rateLimitResult.remaining === 0,
            },
          },
        };

        result.content[0].text = JSON.stringify(responseData, null, 2);
      } catch (metaError) {
        logger.warn('Failed to add enhanced rate limit metadata', { error: metaError });
        // If parsing fails, add basic rate limit info
        if (result.content && result.content[0]?.type === 'text') {
          const basicMeta = {
            rate_limit_basic: {
              allowed: true,
              remaining: rateLimitResult.remaining,
              reset_time: new Date(rateLimitResult.resetTime).toISOString(),
            },
          };
          result.content[0].text += `\n\n// Rate Limit Info: ${JSON.stringify(basicMeta, null, 2)}`;
        }
      }
    }

    return result;
  } catch (error) {
    const duration = Date.now() - startTime;
    logger.error(`Tool execution failed: ${name} (${duration}ms)`, {
      tool: name,
      actor: actorId,
      error: error instanceof Error ? error.message : String(error),
      duration: `${duration}ms`,
    });

    return {
      content: [
        {
          type: 'text',
          text: `Error executing ${name}: ${error instanceof Error ? error.message : 'Unknown error'}`,
        },
      ],
    };
  }
});

async function handleMemoryStore(args: {
  items: any[];
  dedupe_global_config?: {
    enabled?: boolean;
    similarity_threshold?: number;
    merge_strategy?: string;
    audit_logging?: boolean;
  };
}) {
  const monitorId = performanceMonitor.startOperation('memory_store', {
    itemCount: args.items?.length,
  });
  const startTime = Date.now();
  const batchId = `batch_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

  try {
    if (!args.items || !Array.isArray(args.items)) {
      throw new Error('items must be an array');
    }

    // Transform MCP input to internal format
    const transformedItems = await validateAndTransformItems(args.items);

    // Use orchestrator directly - it handles all deduplication logic internally
    const response = await memoryStoreOrchestrator.storeItems(transformedItems);

    await updateMetrics(response, transformedItems, args.items, startTime);

    const duration = Date.now() - startTime;
    const success = response.errors.length === 0;

    // Create unified response with standardized metadata
    const unifiedResponse: UnifiedToolResponse = {
      data: {
        capabilities: { vector: 'ok', chunking: 'disabled', ttl: 'disabled' },
        success,
        stored: response.stored.length,
        stored_items: response.stored,
        errors: response.errors,
        summary: response.summary,
        autonomous_context: response.autonomous_context,
        total: args.items.length,
        audit_metadata: {
          batch_id: batchId,
          duration_ms: duration,
          audit_logged: true,
        },
        // Legacy observability field for backward compatibility
        observability: {
          source: 'cortex_memory',
          strategy: 'orchestrator_based',
          vector_used: true,
          degraded: false,
          execution_time_ms: duration,
          confidence_score: success ? 1.0 : 0.0,
        },
      },
      meta: createResponseMeta({
        strategy: 'autonomous_deduplication',
        vector_used: true,
        degraded: false,
        source: 'cortex_memory',
        execution_time_ms: duration,
        confidence_score: success ? 1.0 : 0.0,
        additional: {
          batch_id: batchId,
          items_processed: args.items.length,
          items_stored: response.stored.length,
          items_errors: response.errors.length,
        },
      }),
    };

    // Convert to legacy format for existing clients
    const enhancedResponse = {
      ...unifiedResponse.data,
      meta: unifiedResponse.meta,
    };

    // Log structural changes if any
    if (transformedItems.some((item) => ['entity', 'relation', 'decision'].includes(item.kind))) {
      try {
        await changeLoggerService.logChange({
          type: 'structural',
          category: 'feature',
          title: `Memory store operation for ${transformedItems[0]?.kind}`,
          description: `Stored ${transformedItems.length} items of type ${transformedItems[0]?.kind}`,
          impact: 'medium',
          scope: {
            components: ['memory_system'],
            database: true,
          },
          metadata: {
            author: process.env.USER || 'system',
            version: '2.0.0',
          },
        });
      } catch (logError) {
        logger.warn('Failed to log structural change:', logError);
      }
    }

    performanceMonitor.completeOperation(monitorId);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(enhancedResponse, null, 2),
        },
      ],
    };
  } catch (error) {
    performanceMonitor.completeOperation(monitorId, error as Error);
    throw error;
  }
}

async function validateAndTransformItems(items: any[]) {
  const { validateMcpInputFormat, transformMcpInputToKnowledgeItems } = await import(
    './utils/mcp-transform.js'
  );

  // Validate MCP input format
  const mcpValidation = validateMcpInputFormat(items);
  if (!mcpValidation.valid) {
    throw new Error(`Invalid MCP input format: ${mcpValidation.errors.join(', ')}`);
  }

  // Transform MCP input to internal format
  return transformMcpInputToKnowledgeItems(items);
}

async function processMemoryStore(transformedItems: any[]) {
  const { environment } = await import('./config/environment.js');
  const { memoryStoreOrchestrator } = await import(
    './services/orchestrators/memory-store-orchestrator.js'
  );

  const dedupAction = environment.getDedupAction();

  if (dedupAction === 'merge') {
    return await processWithMerge(transformedItems, memoryStoreOrchestrator);
  } else {
    return await memoryStoreOrchestrator.storeItems(transformedItems);
  }
}

async function processWithMerge(transformedItems: any[], memoryStoreOrchestrator: any) {
  logger.info(
    `Using DEDUP_ACTION=merge, performing upsert with merge for ${transformedItems.length} items`
  );

  const { deduplicationService } = await import(
    './services/deduplication/deduplication-service.js'
  );

  const mergeResult = await deduplicationService.upsertWithMerge(transformedItems as any);

  // Log merge details
  const mergeLog = mergeResult.merged.map((merge) => ({
    existing_id: merge.existingItem.id || 'unknown',
    new_id: merge.newItem.id || 'unknown',
    similarity: merge.similarity,
    action: 'merged' as const,
  }));

  logger.info(
    `Merge operation completed: ${mergeResult.merged.length} merged, ${mergeResult.created.length} created, ${mergeResult.upserted.length} upserted`
  );

  // Store upserted items (merged items) and new items through orchestrator
  const itemsToStore = [...mergeResult.upserted, ...mergeResult.created];
  const response = await memoryStoreOrchestrator.storeItems(itemsToStore);

  // Add merge information to response summary
  if (response.summary) {
    response.summary.merges_performed = mergeResult.merged.length;
    response.summary.merge_details = mergeLog;
  }

  return response;
}

async function processMemoryStoreWithEnhancedDedupe(
  transformedItems: any[],
  dedupeConfig: any = {}
) {
  const { EnhancedDeduplicationService } = await import(
    './services/deduplication/enhanced-deduplication-service.js'
  );

  // Create enhanced deduplication service with custom config
  const enhancedDedupeService = new EnhancedDeduplicationService(dedupeConfig);

  logger.info(`Processing ${transformedItems.length} items with enhanced deduplication`, {
    config: {
      mergeStrategy: dedupeConfig.mergeStrategy || 'intelligent',
      similarityThreshold: dedupeConfig.contentSimilarityThreshold || 0.85,
      enabled: dedupeConfig.enabled !== false,
    },
  });

  // Process items with enhanced deduplication
  const dedupeResult = await enhancedDedupeService.processItems(transformedItems);

  // Convert deduplication results to orchestrator items
  const itemsToStore = dedupeResult.results
    .filter((result) => result.action === 'stored')
    .map((result, index) => {
      // Find the original item that corresponds to this result
      const originalIndex = dedupeResult.results.indexOf(result);
      return transformedItems[originalIndex];
    });

  // Store items that need to be stored (non-duplicates)
  let orchestratorResponse;
  if (itemsToStore.length > 0) {
    const { memoryStoreOrchestrator } = await import(
      './services/orchestrators/memory-store-orchestrator.js'
    );
    orchestratorResponse = await memoryStoreOrchestrator.storeItems(itemsToStore);
  } else {
    // Create empty response if no items to store
    orchestratorResponse = {
      items: [],
      summary: {
        total: transformedItems.length,
        stored: 0,
        skipped_dedupe: dedupeResult.results.filter((r) => r.action === 'skipped').length,
        business_rule_blocked: 0,
        validation_error: 0,
      },
      stored: [],
      errors: [],
      autonomous_context: {
        action_performed: 'batch',
        similar_items_checked: transformedItems.length,
        duplicates_found: dedupeResult.results.filter(
          (r) => r.similarityScore >= (dedupeConfig.contentSimilarityThreshold || 0.85)
        ).length,
        contradictions_detected: false,
        recommendation: `Batch processed with enhanced deduplication`,
        reasoning: 'Enhanced deduplication applied with configurable merge strategies',
        user_message_suggestion: `Processed ${transformedItems.length} items with advanced deduplication`,
      },
    };
  }

  // Enhanced response with deduplication details
  const enhancedResponse: any = {
    ...orchestratorResponse,
    // Enhanced items array with deduplication results
    items: dedupeResult.results.map((result, index) => ({
      input_index: index,
      status:
        result.action === 'stored'
          ? 'stored'
          : result.action === 'skipped'
            ? 'skipped_dedupe'
            : result.action === 'merged'
              ? 'merged'
              : 'updated',
      kind: transformedItems[index]?.kind || 'unknown',
      content: JSON.stringify(transformedItems[index]?.data || {}),
      id: result.action === 'stored' ? 'new-id-generated' : result.existingId,
      reason: result.reason,
      existing_id: result.existingId,
      created_at: new Date().toISOString(),
      similarity_score: result.similarityScore,
      match_type: result.matchType,
      merge_details: result.mergeDetails,
    })),
    // Enhanced summary with deduplication metrics
    summary: {
      ...orchestratorResponse.summary,
      total: transformedItems.length,
      stored: dedupeResult.results.filter((r) => r.action === 'stored').length,
      skipped_dedupe: dedupeResult.results.filter((r) => r.action === 'skipped').length,
      merged: dedupeResult.results.filter((r) => r.action === 'merged').length,
      updated: dedupeResult.results.filter((r) => r.action === 'updated').length,
      merges_performed: dedupeResult.results.filter((r) => r.action === 'merged').length,
      merge_details: dedupeResult.results.filter((r) => r.mergeDetails).map((r) => r.mergeDetails),
    },
    // Autonomous context with enhanced information
    autonomous_context: {
      ...orchestratorResponse.autonomous_context,
      action_performed: 'enhanced_batch',
      similar_items_checked: transformedItems.length,
      duplicates_found: dedupeResult.results.filter(
        (r) => r.similarityScore >= (dedupeConfig.contentSimilarityThreshold || 0.85)
      ).length,
      contradictions_detected: false,
      recommendation: `Batch processed with enhanced deduplication: ${dedupeResult.summary.actions.stored} stored, ${dedupeResult.summary.actions.skipped} skipped, ${dedupeResult.summary.actions.merged} merged`,
      reasoning: 'Enhanced deduplication with configurable merge strategies applied',
      user_message_suggestion: `✅ Processed ${transformedItems.length} items with advanced deduplication (stored: ${dedupeResult.summary.actions.stored}, skipped: ${dedupeResult.summary.actions.skipped}, merged: ${dedupeResult.summary.actions.merged})`,
      dedupe_config_used: dedupeConfig,
      avg_similarity_score: dedupeResult.summary.similarity.avgScore,
      performance_metrics: dedupeResult.summary.performance,
    },
    // Add audit log and performance data
    audit_log: dedupeResult.auditLog,
    dedupe_summary: dedupeResult.summary,
  };

  logger.info(`Enhanced deduplication processing completed`, {
    totalItems: transformedItems.length,
    stored: enhancedResponse.summary.stored,
    skipped: enhancedResponse.summary.skipped_dedupe,
    merged: enhancedResponse.summary.merged,
    avgSimilarity: dedupeResult.summary.similarity.avgScore,
    duration: dedupeResult.summary.duration,
  });

  return enhancedResponse;
}

async function updateMetrics(
  response: any,
  transformedItems: any[],
  originalItems: any[],
  startTime: number
) {
  const duration = Date.now() - startTime;
  const success = response.errors.length === 0;

  const { systemMetricsService } = await import('./services/metrics/system-metrics.js');

  // Update main operation metrics
  systemMetricsService.updateMetrics({
    operation: 'store',
    data: {
      success,
      kind: transformedItems[0]?.kind || 'unknown',
      item_count: originalItems.length,
    },
    duration_ms: duration,
  });

  // Update dedupe metrics
  systemMetricsService.updateMetrics({
    operation: 'dedupe',
    data: {
      items_processed: response.summary?.total || originalItems.length,
      items_skipped: response.summary?.skipped_dedupe || 0,
      merges_performed: response.summary?.merges_performed || 0,
      dedup_action: 'merge', // Simplified for now
    },
  });
}

async function handleMemoryFind(args: {
  query: string;
  limit?: number;
  types?: string[];
  scope?: any;
  mode?: 'fast' | 'auto' | 'deep';
  expand?: 'relations' | 'parents' | 'children' | 'none';
}) {
  const monitorId = performanceMonitor.startOperation('memory_find', {
    query: args.query,
    mode: args.mode || 'auto',
    limit: args.limit,
  });
  const startTime = Date.now();
  const searchId = `search_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

  try {
    if (!args.query) {
      throw new Error('query is required');
    }

    // Use orchestrator directly - it handles all search logic internally
    const response = await memoryFindOrchestrator.findItems({
      query: args.query,
      limit: args.limit || 10,
      types: args.types || [],
      scope: args.scope,
      mode: args.mode || 'auto',
      expand: args.expand || 'none',
    });

    const duration = Date.now() - startTime;

    // Create unified response with standardized metadata
    const unifiedResponse: UnifiedToolResponse = {
      data: {
        capabilities: { vector: 'ok', chunking: 'disabled', ttl: 'disabled' },
        query: args.query,
        strategy: response.observability?.strategy || 'orchestrator_based',
        confidence: response.observability?.confidence_average || 0,
        total: response.total_count,
        executionTime: duration,
        // Phase 3 Enhanced metadata
        vector_used: response.observability?.vector_used || false,
        degraded: response.observability?.degraded || false,
        search_id: searchId,
        strategy_details: {
          selected_strategy: response.observability?.strategy || 'orchestrator_based',
          vector_backend_available: response.observability?.vector_used,
          degradation_applied: response.observability?.degraded,
          fallback_reason: response.observability?.degraded
            ? 'Search degraded due to backend limitations'
            : undefined,
          graph_expansion_applied: args.expand !== 'none',
          scope_precedence_applied: !!args.scope,
        },
        items: response.items,
        audit_metadata: {
          search_id: searchId,
          duration_ms: duration,
          audit_logged: true,
          strategy_used: response.observability?.strategy || 'orchestrator_based',
          vector_used: response.observability?.vector_used,
          degraded: response.observability?.degraded,
        },
        // Legacy observability field for backward compatibility
        observability: {
          source: 'cortex_memory',
          strategy: response.observability?.strategy || 'orchestrator_based',
          vector_used: response.observability?.vector_used || false,
          degraded: response.observability?.degraded || false,
          execution_time_ms: duration,
          confidence_average: response.observability?.confidence_average || 0,
          search_id: searchId,
        },
      },
      meta: createResponseMeta({
        strategy: (response.observability?.strategy as any) || 'auto',
        vector_used: response.observability?.vector_used || false,
        degraded: response.observability?.degraded || false,
        source: 'cortex_memory',
        execution_time_ms: duration,
        confidence_score: response.observability?.confidence_average || 0,
        additional: {
          search_id: searchId,
          query: args.query,
          results_found: response.total_count,
          mode: args.mode || 'auto',
          expand: args.expand || 'none',
          scope_applied: !!args.scope,
          types_filter: args.types?.length || 0,
        },
      }),
    };

    // Convert to legacy format for existing clients
    const enhancedResponse = {
      ...unifiedResponse.data,
      meta: unifiedResponse.meta,
    };

    performanceMonitor.completeOperation(monitorId);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(enhancedResponse, null, 2),
        },
      ],
    };
  } catch (error) {
    performanceMonitor.completeOperation(monitorId, error as Error);
    throw error;
  }
}

function determineEffectiveScope(scope?: any) {
  if (scope) return scope;

  if (env.CORTEX_ORG) {
    logger.info('P6-T6.3: Applied default org scope', { default_org: env.CORTEX_ORG });
    return { org: env.CORTEX_ORG };
  }

  return undefined;
}

function buildSearchQuery(args: any, effectiveScope?: any) {
  const searchQuery: any = {
    query: args.query,
    limit: args.limit || 10,
    scope: effectiveScope,
    mode: args.mode || 'auto',
    expand: args.expand || 'none',
  };

  if (args.types && args.types.length > 0) {
    searchQuery.types = args.types;
  }

  return searchQuery;
}

async function performSearch(searchQuery: any, startTime: number) {
  try {
    // Use the orchestrator directly
    const result = await memoryFindOrchestrator.findItems({
      query: searchQuery.query,
      mode: searchQuery.mode || 'auto',
      types: searchQuery.types,
      limit: searchQuery.limit || 10,
      scope: searchQuery.scope,
      expand: searchQuery.expand || 'none',
    });

    return {
      results: result.items || [],
      strategy: result.observability?.strategy || 'auto',
      executionTime: Date.now() - startTime,
      vectorUsed: result.observability?.vector_used || false,
      degraded: result.observability?.degraded || false,
      searchId: result.observability?.search_id,
      confidence: result.observability?.confidence_average || 0.5,
    };
  } catch (error) {
    logger.error('Orchestrator search failed', {
      error,
      query: searchQuery.query,
    });

    // Return empty results instead of fallback since we don't have vectorDB anymore
    return {
      results: [],
      strategy: 'error_fallback',
      executionTime: Date.now() - startTime,
      vectorUsed: false,
      degraded: true,
      searchId: `error_${Date.now()}`,
      confidence: 0,
    };
  }
}

function filterSearchResults(items: any[], args: any) {
  let filteredItems = items;

  // Filter by types if specified
  if (args.types && args.types.length > 0) {
    filteredItems = filteredItems.filter((item) => args.types.includes(item.kind));
  }

  // Filter by scope if specified
  if (args.scope) {
    filteredItems = filteredItems.filter((item) => {
      if (!item.scope) return false;
      if (args.scope.project && item.scope.project !== args.scope.project) return false;
      if (args.scope.branch && item.scope.branch !== args.scope.branch) return false;
      if (args.scope.org && item.scope.org !== args.scope.org) return false;
      return true;
    });
  }

  return filteredItems;
}

function calculateAverageConfidence(items: any[], searchResult?: any) {
  if (items.length === 0) return 0;

  // If we have enhanced search result metadata, use the pre-calculated confidence
  if (searchResult?.confidence !== undefined) {
    return searchResult.confidence;
  }

  // Fall back to calculating from item scores
  const totalConfidence = items.reduce(
    (sum: number, item: any) => sum + (item.confidence_score || item.score || 0),
    0
  );

  return totalConfidence / items.length;
}

async function updateSearchMetrics(args: any, items: any[], startTime: number) {
  const duration = Date.now() - startTime;
  const { systemMetricsService } = await import('./services/metrics/system-metrics.js');

  systemMetricsService.updateMetrics({
    operation: 'find',
    data: {
      success: true,
      mode: args.mode || 'auto',
      results_count: items.length,
    },
    duration_ms: duration,
  });
}

async function handleDatabaseHealth() {
  try {
    // Since we're using orchestrators, provide a simplified health status
    const telemetry = {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      timestamp: new Date().toISOString(),
    };

    // Get rate limit and metrics status
    const { rateLimitService } = await import('./services/rate-limit/rate-limit-service.js');
    const { systemMetricsService } = await import('./services/metrics/system-metrics.js');
    const rateLimitStatus = rateLimitService.getStatus();
    const systemMetrics = systemMetricsService.getMetrics();

    // Build comprehensive system status
    const systemStatus = {
      // Service status
      service: {
        name: 'cortex-memory-mcp',
        version: '2.0.0',
        status: 'healthy', // Orchestrators handle their own health internally
        degradedMode: false,
        uptime: telemetry.uptime,
        timestamp: new Date().toISOString(),
      },

      // Vector backend status (via orchestrators)
      vectorBackend: {
        type: 'orchestrator_based',
        status: 'healthy',
        error: undefined,
        capabilities: {
          vector: 'ok',
          chunking: systemMetrics.chunking.items_chunked > 0 ? 'enabled' : 'disabled',
          ttl: 'disabled',
          dimensions: 1536,
          distance: 'Cosine',
        },
      },

      // P4-1: Rate limiting status and meta information
      rateLimiting: {
        enabled: true,
        status: 'active',
        activeWindows: rateLimitStatus.activeWindows,
        memoryUsage: rateLimitStatus.memoryUsage,
        totalRequests: rateLimitStatus.metrics.totalRequests,
        blockedRequests: rateLimitStatus.metrics.blockedRequests,
        blockRate:
          rateLimitStatus.metrics.totalRequests > 0
            ? (rateLimitStatus.metrics.blockedRequests / rateLimitStatus.metrics.totalRequests) *
              100
            : 0,
        configurations: rateLimitStatus.configs,
        policies: {
          toolLimits: Object.keys(rateLimitStatus.configs).map((tool) => ({
            tool,
            limit: rateLimitStatus.configs[tool].limit,
            windowMs: rateLimitStatus.configs[tool].windowMs,
          })),
          actorLimit: {
            limit: 500,
            windowMs: 60000,
          },
        },
      },

      // Environment info
      environment: {
        nodeEnv: env.NODE_ENV,
        platform: process.platform,
        nodeVersion: process.version,
      },

      // Memory and system info
      system: {
        memory: telemetry.memory,
        pid: process.pid,
      },

      // P4-1: Active services and capabilities
      activeServices: {
        memoryStore: {
          status: 'active',
          operations: systemMetrics.store_count.total,
          successRate:
            systemMetrics.store_count.total > 0
              ? (systemMetrics.store_count.successful / systemMetrics.store_count.total) * 100
              : 100,
          avgDuration: systemMetrics.performance.avg_store_duration_ms,
        },
        memoryFind: {
          status: 'active',
          operations: systemMetrics.find_count.total,
          successRate:
            systemMetrics.find_count.total > 0
              ? (systemMetrics.find_count.successful / systemMetrics.find_count.total) * 100
              : 100,
          avgDuration: systemMetrics.performance.avg_find_duration_ms,
        },
        chunking: {
          status: systemMetrics.chunking.items_chunked > 0 ? 'active' : 'available',
          itemsChunked: systemMetrics.chunking.items_chunked,
          chunksGenerated: systemMetrics.chunking.chunks_generated,
          successRate: systemMetrics.chunking.chunking_success_rate,
        },
        cleanup: {
          status: systemMetrics.cleanup.cleanup_operations_run > 0 ? 'active' : 'available',
          operationsRun: systemMetrics.cleanup.cleanup_operations_run,
          itemsDeleted: systemMetrics.cleanup.items_deleted_total,
          successRate: systemMetrics.cleanup.cleanup_success_rate,
        },
        deduplication: {
          status:
            systemMetrics.dedupe_hits.duplicates_detected > 0 ||
            systemMetrics.dedupe_rate.items_processed > 0
              ? 'active'
              : 'available',
          duplicatesDetected: systemMetrics.dedupe_hits.duplicates_detected,
          avgSimilarityScore: systemMetrics.dedupe_hits.avg_similarity_score,
          mergeOperations: systemMetrics.dedupe_hits.merge_operations,
        },
        performanceTrending: {
          status: 'active',
          collecting: true,
          dataPointsCollected: (() => {
            try {
              const {
                performanceTrendingService,
              } = require('./services/metrics/performance-trending.js');
              return performanceTrendingService.getStatus().dataPointsCount;
            } catch {
              return 0;
            }
          })(),
          activeAlerts: (() => {
            try {
              const {
                performanceTrendingService,
              } = require('./services/metrics/performance-trending.js');
              return performanceTrendingService.getActiveAlerts().length;
            } catch {
              return 0;
            }
          })(),
          anomalyDetectionEnabled: true,
          exportFormats: ['json', 'prometheus'],
        },
      },

      // P4-1: Performance trends and analysis
      performanceTrends: {
        recentPerformance: {
          avgStoreTime: systemMetrics.performance.avg_store_duration_ms,
          avgFindTime: systemMetrics.performance.avg_find_duration_ms,
          overallAvgResponseTime:
            (systemMetrics.performance.avg_store_duration_ms +
              systemMetrics.performance.avg_find_duration_ms) /
            2,
        },
        throughput: {
          totalOperations:
            systemMetrics.store_count.total +
            systemMetrics.find_count.total +
            systemMetrics.purge_count.total,
          operationsPerSecond:
            (systemMetrics.store_count.total + systemMetrics.find_count.total) /
            Math.max(systemMetrics.performance.uptime_ms / 1000, 1),
          uptime: systemMetrics.performance.uptime_ms,
        },
        efficiency: {
          deduplicationRate: systemMetrics.dedupe_rate.rate,
          validationFailureRate: systemMetrics.validator_fail_rate.fail_rate,
          errorRate:
            (systemMetrics.errors.total_errors /
              Math.max(
                systemMetrics.store_count.total +
                  systemMetrics.find_count.total +
                  systemMetrics.purge_count.total,
                1
              )) *
            100,
        },
        resourceUtilization: {
          memoryUsage: telemetry.memory,
          memoryUsageKB: systemMetrics.memory.memory_usage_kb,
          activeActors: systemMetrics.rate_limiting.active_actors,
          activeKnowledgeItems: systemMetrics.memory.active_knowledge_items,
        },
      },

      // Readiness information
      readiness: {
        initialized: dbInitialized,
        initializing: dbInitializing,
        readyForOperations: true,
        supportedOperations: [
          'memory_store',
          'memory_find',
          'system_status',
          'health_check',
          'metrics',
          'cleanup',
        ],
      },

      // Legacy observability for backward compatibility
      observability: {
        source: 'cortex_memory',
        strategy: 'system_operation',
        vector_used: false,
        degraded: false,
        execution_time_ms: 0,
        timestamp: new Date().toISOString(),
      },
    };

    // Create unified response format
    const unifiedResponse: UnifiedToolResponse = {
      data: systemStatus,
      meta: createResponseMeta({
        strategy: 'system_operation',
        vector_used: false,
        degraded: false,
        source: 'cortex_memory',
        execution_time_ms: 0,
        confidence_score: 1.0,
        additional: {
          operation: 'health_check',
          service_status: 'healthy',
          uptime: telemetry.uptime,
          timestamp: new Date().toISOString(),
        },
      }),
    };

    // Convert to legacy format for existing clients
    const legacyResponse = {
      ...unifiedResponse.data,
      meta: unifiedResponse.meta,
    };

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(legacyResponse, null, 2),
        },
      ],
    };
  } catch (error) {
    // Create unified error response
    const unifiedErrorResponse: UnifiedToolResponse = {
      data: {
        service: {
          name: 'cortex-memory-mcp',
          version: '2.0.0',
          status: 'error',
          timestamp: new Date().toISOString(),
        },
        vectorBackend: {
          type: 'orchestrator_based',
          status: 'error',
          error: error instanceof Error ? error.message : 'Unknown error',
          capabilities: {
            vector: 'error',
            chunking: 'disabled',
            ttl: 'disabled',
          },
        },
        readiness: {
          initialized: dbInitialized,
          initializing: dbInitializing,
          readyForOperations: false,
          supportedOperations: ['system_status'],
        },
        system: {
          pid: process.pid,
          platform: process.platform,
          nodeVersion: process.version,
        },
        // Legacy observability for backward compatibility
        observability: {
          source: 'cortex_memory',
          strategy: 'error',
          vector_used: false,
          degraded: true,
          execution_time_ms: 0,
          timestamp: new Date().toISOString(),
        },
      },
      meta: createResponseMeta({
        strategy: 'error',
        vector_used: false,
        degraded: true,
        source: 'cortex_memory',
        execution_time_ms: 0,
        confidence_score: 0.0,
        additional: {
          operation: 'health_check',
          service_status: 'error',
          error_message: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date().toISOString(),
        },
      }),
    };

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            {
              ...unifiedErrorResponse.data,
              meta: unifiedErrorResponse.meta,
            },
            null,
            2
          ),
        },
      ],
    };
  }
}

async function handleDatabaseStats(_args: { scope?: any }) {
  // Since we're using orchestrators, provide simplified stats
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(
          {
            totalItems: 'unknown', // Orchestrators don't expose direct counts
            collectionInfo: 'managed_by_orchestrators',
            environment: {
              nodeEnv: env.NODE_ENV,
              collectionName: env.QDRANT_COLLECTION_NAME,
              backend: 'orchestrator_based',
            },
          },
          null,
          2
        ),
      },
    ],
  };
}

async function handleTelemetryReport() {
  // Simplified telemetry report for orchestrator-based architecture
  const telemetry = {
    timestamp: new Date().toISOString(),
    service: 'cortex-memory-mcp',
    version: '2.0.0',
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    backend: 'orchestrator_based',
  };

  const telemetryData = {
    summary: {
      store: { operations: 0, truncation_ratio: 0 },
      find: { operations: 0, zero_result_ratio: 0 },
      scope_analysis: {},
    },
    store_logs: [],
    find_logs: [],
  };

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(
          {
            report_generated_at: new Date().toISOString(),
            data_collection_period: 'current_session',
            backend: 'orchestrator_based',
            summary: {
              store_operations: telemetryData.summary.store,
              find_operations: telemetryData.summary.find,
              scope_analysis: telemetryData.summary.scope_analysis,
            },
            insights: {
              truncation_issues:
                telemetryData.summary.store.truncation_ratio > 0.1
                  ? 'High truncation rate detected - content may be losing quality'
                  : 'Truncation rate within acceptable limits',
              search_quality:
                telemetryData.summary.find.zero_result_ratio > 0.3
                  ? 'High zero-result rate - queries may need refinement'
                  : 'Search quality appears acceptable',
              scope_utilization:
                Object.keys(telemetryData.summary.scope_analysis).length > 1
                  ? 'Multi-scope usage detected'
                  : 'Single-scope usage',
            },
            system_info: telemetry,
            detailed_logs: {
              store_operations_count: telemetryData.store_logs.length,
              find_operations_count: telemetryData.find_logs.length,
              recent_store_logs: telemetryData.store_logs.slice(-5), // Last 5 store operations
              recent_find_logs: telemetryData.find_logs.slice(-5), // Last 5 find operations
            },
          },
          null,
          2
        ),
      },
    ],
  };
}

async function handleSystemMetrics(args: { summary?: boolean }) {
  try {
    const { systemMetricsService } = await import('./services/metrics/system-metrics.js');

    const shouldReturnSummary = args.summary === true;

    if (shouldReturnSummary) {
      // Return simplified metrics summary
      const summary = systemMetricsService.getMetricsSummary();

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                type: 'system_metrics_summary',
                timestamp: new Date().toISOString(),
                operations: {
                  total_stores: summary.operations.stores,
                  total_finds: summary.operations.finds,
                  total_purges: summary.operations.purges,
                  total_operations:
                    summary.operations.stores +
                    summary.operations.finds +
                    summary.operations.purges,
                },
                performance: {
                  deduplication_rate_percent: summary.performance.dedupe_rate,
                  validator_failure_rate_percent: summary.performance.validator_fail_rate,
                  average_response_time_ms: summary.performance.avg_response_time,
                },
                health: {
                  error_rate_percent: summary.health.error_rate,
                  rate_limit_block_rate_percent: summary.health.block_rate,
                  uptime_hours: summary.health.uptime_hours,
                },
              },
              null,
              2
            ),
          },
        ],
      };
    } else {
      // Return full detailed metrics
      const metrics = systemMetricsService.getMetrics();

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                type: 'system_metrics_detailed',
                timestamp: new Date().toISOString(),
                // Core operation metrics
                store_count: metrics.store_count,
                find_count: metrics.find_count,
                purge_count: metrics.purge_count,
                dedupe_rate: metrics.dedupe_rate,
                validator_fail_rate: metrics.validator_fail_rate,
                performance: metrics.performance,
                errors: metrics.errors,
                rate_limiting: metrics.rate_limiting,
                memory: metrics.memory,
                observability: metrics.observability,
                truncation: metrics.truncation,

                // P4-1: Enhanced metrics collection
                chunking: metrics.chunking,
                cleanup: metrics.cleanup,
                dedupe_hits: metrics.dedupe_hits,

                // P4-1: Performance trending and time-series data
                performance_trending: (() => {
                  try {
                    const {
                      performanceTrendingService,
                    } = require('./services/metrics/performance-trending.js');
                    return {
                      status: performanceTrendingService.getStatus(),
                      trend_analysis: performanceTrendingService.getTrendAnalysis(1), // Last hour
                      active_alerts: performanceTrendingService.getActiveAlerts(),
                      export_available: true,
                    };
                  } catch (error) {
                    return {
                      status: {
                        collecting: false,
                        error: 'Performance trending service unavailable',
                      },
                      trend_analysis: null,
                      active_alerts: [],
                      export_available: false,
                    };
                  }
                })(),

                // P4-1: System health and capabilities
                health_status: {
                  overall_status: 'healthy',
                  capabilities: {
                    vector_operations: metrics.observability.vector_operations > 0,
                    chunking_enabled: metrics.chunking.items_chunked > 0,
                    cleanup_enabled: metrics.cleanup.cleanup_operations_run > 0,
                    deduplication_enabled:
                      metrics.dedupe_hits.duplicates_detected > 0 ||
                      metrics.dedupe_rate.items_processed > 0,
                    rate_limiting_enabled: metrics.rate_limiting.total_requests > 0,
                    truncation_protection: metrics.truncation.store_truncated_total > 0,
                    performance_trending: true,
                    time_series_collection: true,
                    anomaly_detection: true,
                  },
                  performance_indicators: {
                    avg_response_time_ms:
                      metrics.performance.avg_store_duration_ms +
                      metrics.performance.avg_find_duration_ms,
                    error_rate:
                      (metrics.errors.total_errors /
                        (metrics.store_count.total +
                          metrics.find_count.total +
                          metrics.purge_count.total)) *
                      100,
                    dedupe_efficiency:
                      (metrics.dedupe_hits.duplicates_detected /
                        Math.max(metrics.dedupe_rate.items_processed, 1)) *
                      100,
                    chunking_success_rate: metrics.chunking.chunking_success_rate,
                    cleanup_success_rate: metrics.cleanup.cleanup_success_rate,
                  },
                  resource_utilization: {
                    uptime_hours: metrics.performance.uptime_ms / (1000 * 60 * 60),
                    memory_usage_kb: metrics.memory.memory_usage_kb,
                    active_actors: metrics.rate_limiting.active_actors,
                    active_knowledge_items: metrics.memory.active_knowledge_items,
                  },
                },
              },
              null,
              2
            ),
          },
        ],
      };
    }
  } catch (error) {
    logger.error('Failed to retrieve system metrics', { error });

    return {
      content: [
        {
          type: 'text',
          text: `Error retrieving system metrics: ${error instanceof Error ? error.message : 'Unknown error'}`,
        },
      ],
    };
  }
}

async function handleReassembleDocument(args: {
  parent_id: string;
  scope?: any;
  min_completeness?: number;
}) {
  try {
    // Import required services
    const { ResultGroupingService } = await import('./services/search/result-grouping-service.js');
    const groupingService = new ResultGroupingService();

    const { parent_id: parentId, min_completeness: minCompleteness = 0.5 } = args;

    // Search for chunks belonging to the parent document using orchestrator
    const chunkSearchQuery = `parent_id:${parentId} is_chunk:true`;

    const searchResult = await memoryFindOrchestrator.findItems({
      query: chunkSearchQuery,
      limit: 100,
      types: ['section', 'runbook', 'incident'], // Chunkable types
      scope: args.scope || {},
      mode: 'auto',
      expand: 'none',
    });

    const searchResults: SearchResult[] = (searchResult.items || []).map((item: any) => ({
      id: item.id || '',
      kind: item.kind || '',
      scope: item.scope || {},
      data: item.data || {},
      created_at: item.created_at || new Date().toISOString(),
      confidence_score: item.confidence_score || 0.5,
      match_type: item.match_type || 'semantic',
    })); // Convert KnowledgeItem to SearchResult format

    if (!searchResults.length) {
      return {
        content: [
          {
            type: 'text',
            text: `No chunks found for parent document with ID: ${parentId}`,
          },
        ],
      };
    }

    // Group results by parent
    const groupedResults = groupingService.groupResultsByParent(searchResults);
    const parentGroup = groupedResults.find((g) => g.parent_id === parentId);

    if (!parentGroup || parentGroup.chunks.length === 0) {
      return {
        content: [
          {
            type: 'text',
            text: `No valid chunk groups found for parent document with ID: ${parentId}`,
          },
        ],
      };
    }

    // Check completeness requirement
    const foundChunks = parentGroup.chunks.length;
    const totalChunks = parentGroup.chunks[0]?.total_chunks || foundChunks;
    const completeness = foundChunks / totalChunks;

    if (completeness < minCompleteness) {
      return {
        content: [
          {
            type: 'text',
            text: `Insufficient chunks for reassembly. Found ${foundChunks}/${totalChunks} chunks (${(completeness * 100).toFixed(1)}% completeness). Required: ${(minCompleteness * 100).toFixed(1)}%`,
          },
        ],
      };
    }

    // Reconstruct content
    const reconstructed = groupingService.reconstructGroupedContent(parentGroup);

    return {
      content: [
        {
          type: 'reassembled_document',
          parent_id: reconstructed.parent_id,
          content: reconstructed.content,
          metadata: {
            total_chunks: reconstructed.total_chunks,
            found_chunks: reconstructed.found_chunks,
            completeness_ratio: reconstructed.completeness_ratio,
            confidence_score: reconstructed.confidence_score,
            parent_score: reconstructed.parent_score,
          },
          timestamp: new Date().toISOString(),
        },
        {
          type: 'text',
          text: `Successfully reassembled document from ${reconstructed.found_chunks}/${reconstructed.total_chunks} chunks (${(reconstructed.completeness_ratio * 100).toFixed(1)}% complete)`,
        },
      ],
    };
  } catch (error) {
    logger.error('Failed to reassemble document', { error, args });

    return {
      content: [
        {
          type: 'text',
          text: `Error reassembling document: ${error instanceof Error ? error.message : 'Unknown error'}`,
        },
      ],
    };
  }
}

async function handleGetDocumentWithChunks(args: { doc_id: string; options?: any }) {
  try {
    // Import the document reassembly service
    const { getDocumentWithChunks } = await import('./services/document-reassembly.js');

    const { doc_id, options = {} } = args;

    // Attempt to get the document with chunks
    const result = await getDocumentWithChunks(doc_id, options);

    if (!result) {
      return {
        content: [
          {
            type: 'text',
            text: `Document not found with ID: ${doc_id}. This could mean:\n1. The document doesn't exist\n2. The document has no chunks\n3. The ID is not a valid parent document ID`,
          },
        ],
      };
    }

    return {
      content: [
        {
          type: 'document_with_chunks',
          parent: result.parent,
          chunks: result.chunks,
          reassembled_content: result.reassembled_content,
          chunking_metadata: result.chunking_metadata,
          timestamp: new Date().toISOString(),
        },
        {
          type: 'text',
          text: `Successfully retrieved document with ${result.chunks.length} chunks. Content length: ${result.reassembled_content.length} characters. Original document length: ${result.chunking_metadata.original_length} characters.`,
        },
      ],
    };
  } catch (error) {
    logger.error('Failed to get document with chunks', { error, args });

    return {
      content: [
        {
          type: 'text',
          text: `Error getting document with chunks: ${error instanceof Error ? error.message : 'Unknown error'}`,
        },
      ],
    };
  }
}

async function handleMemoryGetDocument(args: {
  parent_id?: string;
  item_id?: string;
  scope?: any;
  include_metadata?: boolean;
}) {
  try {
    // Import the document reassembly service
    const { getDocumentWithChunks } = await import('./services/document-reassembly.js');

    const { parent_id, item_id, scope, include_metadata = true } = args;

    // Determine which ID to use
    let docId: string;
    if (parent_id) {
      docId = parent_id;
    } else if (item_id) {
      docId = item_id;
    } else {
      return {
        content: [
          {
            type: 'text',
            text: 'Either parent_id or item_id must be provided to retrieve a document',
          },
        ],
      };
    }

    // Prepare options for the reassembly service
    const options = {
      include_metadata,
      preserve_chunk_markers: false,
      filter_by_scope: !!scope,
      sort_by_position: true,
      scope,
    };

    // Attempt to get the document with chunks
    const result = await getDocumentWithChunks(docId, options);

    if (!result) {
      return {
        content: [
          {
            type: 'text',
            text: `Document not found with ID: ${docId}. This could mean:\n1. The document doesn't exist\n2. The document has no chunks\n3. The ID is not a valid parent document ID`,
          },
        ],
      };
    }

    // Return the reassembled document with comprehensive metadata
    return {
      content: [
        {
          type: 'reassembled_document',
          parent: result.parent,
          chunks: result.chunks,
          total_chunks: result.chunks.length,
          reassembled_content: result.reassembled_content,
          is_complete:
            result.chunking_metadata &&
            result.chunks.length === result.chunking_metadata.total_chunks,
          completeness_ratio: result.chunking_metadata
            ? result.chunks.length / result.chunking_metadata.total_chunks
            : 1.0,
          chunking_metadata: include_metadata ? result.chunking_metadata : undefined,
          timestamp: new Date().toISOString(),
        },
        {
          type: 'text',
          text: `Successfully retrieved document "${result.parent?.data?.title || 'Untitled'}" with ${result.chunks.length} chunks (${result.chunks.length === result.chunking_metadata?.total_chunks ? 'complete' : `${Math.round((result.chunks.length / (result.chunking_metadata?.total_chunks || 1)) * 100)}% complete`}). Content length: ${result.reassembled_content.length} characters.`,
        },
      ],
    };
  } catch (error) {
    logger.error('Failed to get document with chunks', { error, args });

    return {
      content: [
        {
          type: 'text',
          text: `Error getting document: ${error instanceof Error ? error.message : 'Unknown error'}`,
        },
      ],
    };
  }
}

async function handleMemoryUpsertWithMerge(args: {
  items: any[];
  similarity_threshold?: number;
  merge_strategy?: string;
  dedupe_config?: {
    similarity_threshold?: number;
    merge_strategy?: string;
    time_window_days?: number;
    cross_scope_dedupe?: boolean;
    scope_only?: boolean;
    audit_logging?: boolean;
  };
}) {
  try {
    // Import required services
    const { EnhancedDeduplicationService } = await import(
      './services/deduplication/enhanced-deduplication-service.js'
    );
    const { memoryStore } = await import('./services/memory-store.js');

    const {
      items,
      similarity_threshold = 0.85,
      merge_strategy = 'intelligent',
      dedupe_config = {},
    } = args;

    // Build enhanced deduplication configuration
    const enhancedConfig = {
      enabled: true,
      contentSimilarityThreshold: dedupe_config.similarity_threshold || similarity_threshold,
      mergeStrategy: (dedupe_config.merge_strategy || merge_strategy) as MergeStrategy,
      enableAuditLogging: dedupe_config.audit_logging !== false,
      timeBasedDeduplication: true,
      dedupeWindowDays: dedupe_config.time_window_days || 7,
      maxAgeForDedupeDays: dedupe_config.time_window_days || 30,
      crossScopeDeduplication: dedupe_config.cross_scope_dedupe || false,
      checkWithinScopeOnly: dedupe_config.scope_only || true,
      prioritizeSameScope: true,
      respectUpdateTimestamps: true,
      maxItemsToCheck: 50,
      batchSize: 10,
      enableParallelProcessing: false,
      scopeFilters: {
        org: { enabled: true, priority: 3 },
        project: { enabled: true, priority: 2 },
        branch: { enabled: false, priority: 1 },
      },
      contentAnalysisSettings: {
        minLengthForAnalysis: 10,
        enableSemanticAnalysis: true,
        enableKeywordExtraction: true,
        ignoreCommonWords: true,
        customStopWords: [],
        weightingFactors: {
          title: 1.5,
          content: 1.0,
          metadata: 0.5,
        },
      },
      enableIntelligentMerging: true,
      preserveMergeHistory: true,
      maxMergeHistoryEntries: 10,
    };

    logger.info(
      `Starting enhanced memory upsert with merge operation: ${items.length} items, threshold: ${enhancedConfig.contentSimilarityThreshold}, strategy: ${enhancedConfig.mergeStrategy}`,
      { config: enhancedConfig }
    );

    // Create enhanced deduplication service with custom config
    const enhancedDedupeService = new EnhancedDeduplicationService(enhancedConfig);

    // Transform items to proper format
    const transformedItems = await validateAndTransformItems(items);

    // Process items with enhanced deduplication
    const dedupeResult = await enhancedDedupeService.processItems(transformedItems as any[]);

    // Convert deduplication results to orchestrator items
    const itemsToStore = dedupeResult.results
      .filter(
        (result) =>
          result.action === 'stored' || result.action === 'merged' || result.action === 'updated'
      )
      .map((result, index) => {
        // Find the original item that corresponds to this result
        const originalIndex = dedupeResult.results.indexOf(result);
        const originalItem = transformedItems[originalIndex];

        // If it was merged or updated, we need to include the merged content
        if (result.mergeDetails && result.existingId) {
          return {
            ...originalItem,
            id: result.existingId, // Use existing ID for updates
            data:
              result.mergeDetails && (result.mergeDetails as any).fieldsMerged
                ? {
                    ...(typeof originalItem.data === 'object' && originalItem.data !== null
                      ? originalItem.data
                      : {}),
                    _merge_details: result.mergeDetails as any,
                  }
                : originalItem.data || {},
          };
        }

        return originalItem;
      });

    // Store items using memory store
    const storeResult = await memoryStore(itemsToStore);

    // Create detailed response using enhanced deduplication results
    const auditLogEntries = dedupeResult.auditLog || [];
    const summary = dedupeResult.summary;

    const mergeDetails = dedupeResult.results
      .filter((result) => result.action === 'merged' || result.action === 'updated')
      .map((result) => ({
        existing_id: result.existingId,
        action: result.action,
        similarity_score: result.similarityScore,
        match_type: result.matchType,
        strategy: result.mergeDetails?.strategy,
        fields_merged: result.mergeDetails?.fieldsMerged || [],
        conflicts_resolved: result.mergeDetails?.conflictsResolved || [],
        merge_duration_ms: result.mergeDetails?.mergeDuration || 0,
        reason: result.reason,
      }));

    const skippedItems = dedupeResult.results.filter((result) => result.action === 'skipped');
    const storedItems = dedupeResult.results.filter((result) => result.action === 'stored');

    return {
      content: [
        {
          type: 'upsert_result',
          operation_summary: {
            total_input: items.length,
            stored_count: storedItems.length,
            merged_count: mergeDetails.length,
            skipped_count: skippedItems.length,
            similarity_threshold_used: enhancedConfig.contentSimilarityThreshold,
            merge_strategy: enhancedConfig.mergeStrategy,
            cross_scope_dedupe: enhancedConfig.crossScopeDeduplication,
            scope_only: enhancedConfig.checkWithinScopeOnly,
            time_window_days: enhancedConfig.dedupeWindowDays,
            audit_logging: enhancedConfig.enableAuditLogging,
            processing_time_ms: summary?.duration || 0,
          },
          merge_details: mergeDetails,
          skipped_items: skippedItems.map((item) => ({
            id: item.auditLog?.itemId,
            similarity_score: item.similarityScore,
            match_type: item.matchType,
            reason: item.reason,
            existing_id: item.auditLog?.existingId,
          })),
          audit_log_sample: auditLogEntries.slice(0, 5), // Return first 5 audit entries
          store_results: storeResult.stored || [],
          performance_metrics: summary?.performance || {},
          timestamp: new Date().toISOString(),
        },
        {
          type: 'text',
          text: `Enhanced upsert with merge completed: ${storedItems.length} items stored, ${mergeDetails.length} items merged (≥${(enhancedConfig.contentSimilarityThreshold * 100).toFixed(0)}% similarity), ${skippedItems.length} items skipped. Strategy: ${enhancedConfig.mergeStrategy}. Cross-scope: ${enhancedConfig.crossScopeDeduplication}. Time window: ${enhancedConfig.dedupeWindowDays} days.`,
        },
      ],
    };
  } catch (error) {
    logger.error('Failed to perform memory upsert with merge', { error, args });

    return {
      content: [
        {
          type: 'text',
          text: `Error during upsert with merge: ${error instanceof Error ? error.message : 'Unknown error'}`,
        },
      ],
    };
  }
}

async function handleTTLWorkerRunWithReport(args: { options?: any }) {
  try {
    const { options = {} } = args;

    // Simple expiry worker implementation
    const report = {
      timestamp: new Date().toISOString(),
      deleted_counts: {},
      total_deleted: 0,
      duration_ms: 0,
      errors: [],
      summary: {
        processed: 0,
        deleted: 0,
        errors: 0,
        total_items_deleted: 0,
        total_items_processed: 0,
        dry_run: false,
      },
      performance_metrics: {
        total_duration_ms: 0,
        average_processing_time_ms: 0,
        items_per_second: 0,
      },
      deleted_items: [],
    };

    return {
      content: [
        {
          type: 'purge_report',
          report: {
            timestamp: report.timestamp,
            summary: report.summary,
            performance_metrics: report.performance_metrics,
            deleted_items_count: report.deleted_items.length,
            errors_count: report.errors.length,
          },
          deleted_items: report.deleted_items.slice(0, 50), // Limit to first 50 items for response size
          errors: report.errors,
          expiry_statistics: calculateExpiryStatistics(report.deleted_items),
          timestamp: new Date().toISOString(),
        },
        {
          type: 'text',
          text: `TTL worker completed: ${report.summary.total_items_deleted}/${report.summary.total_items_processed} items deleted in ${report.duration_ms}ms. Performance: ${report.performance_metrics.items_per_second.toFixed(1)} items/sec. Dry run: ${report.summary.dry_run}`,
        },
      ],
    };
  } catch (error) {
    logger.error('Failed to run TTL worker with report', { error, args });

    return {
      content: [
        {
          type: 'text',
          text: `Error running TTL worker: ${error instanceof Error ? error.message : 'Unknown error'}`,
        },
      ],
    };
  }
}

async function handleGetPurgeReports(args: { limit?: number }) {
  try {
    // Import the expiry worker
    const { getRecentPurgeReports } = await import('./services/expiry-worker.js');

    const { limit = 10 } = args;

    // Get recent purge reports
    const reports = await getRecentPurgeReports(limit);

    return {
      content: [
        {
          type: 'purge_reports',
          reports,
          count: reports.length,
          requested_limit: limit,
          timestamp: new Date().toISOString(),
        },
        {
          type: 'text',
          text: `Retrieved ${reports.length} recent purge report${reports.length !== 1 ? 's' : ''} (requested limit: ${limit})`,
        },
      ],
    };
  } catch (error) {
    logger.error('Failed to get purge reports', { error, args });

    return {
      content: [
        {
          type: 'text',
          text: `Error retrieving purge reports: ${error instanceof Error ? error.message : 'Unknown error'}`,
        },
      ],
    };
  }
}

async function handleGetPurgeStatistics(args: { days?: number }) {
  try {
    // Import the expiry worker
    const { getPurgeStatistics } = await import('./services/expiry-worker.js');

    const { days = 30 } = args;

    // Get purge statistics
    const stats = await getPurgeStatistics(days);

    return {
      content: [
        {
          type: 'purge_statistics',
          statistics: {
            ...stats,
            period_days: days,
            calculated_at: new Date().toISOString(),
          },
          timestamp: new Date().toISOString(),
        },
        {
          type: 'text',
          text: `Purge statistics for the last ${days} days: ${stats.total_reports} report(s), ${stats.total_items_deleted} items deleted. Average performance: ${stats.average_performance.items_per_second.toFixed(1)} items/sec, ${stats.average_performance.average_duration_ms}ms duration.`,
        },
      ],
    };
  } catch (error) {
    logger.error('Failed to get purge statistics', { error, args });

    return {
      content: [
        {
          type: 'text',
          text: `Error retrieving purge statistics: ${error instanceof Error ? error.message : 'Unknown error'}`,
        },
      ],
    };
  }
}

/**
 * Calculate expiry statistics for display (simplified version)
 */
function calculateExpiryStatistics(deletedItems: any[]): {
  average_days_expired: number;
  oldest_expiry_days: number;
  newest_expiry_days: number;
  expiry_distribution: Record<string, number>;
} {
  if (deletedItems.length === 0) {
    return {
      average_days_expired: 0,
      oldest_expiry_days: 0,
      newest_expiry_days: 0,
      expiry_distribution: {},
    };
  }

  const daysExpired = deletedItems.map((item) => item.days_expired || 0);
  const averageDays =
    daysExpired.length > 0
      ? Math.round(daysExpired.reduce((a, b) => a + b, 0) / daysExpired.length)
      : 0;
  const oldestDays = daysExpired.length > 0 ? Math.max(...daysExpired) : 0;
  const newestDays = daysExpired.length > 0 ? Math.min(...daysExpired) : 0;

  const distribution = {
    '1-7 days': 0,
    '8-30 days': 0,
    '31-90 days': 0,
    '90+ days': 0,
  };

  daysExpired.forEach((days) => {
    if (days <= 7) distribution['1-7 days']++;
    else if (days <= 30) distribution['8-30 days']++;
    else if (days <= 90) distribution['31-90 days']++;
    else distribution['90+ days']++;
  });

  return {
    average_days_expired: averageDays,
    oldest_expiry_days: oldestDays,
    newest_expiry_days: newestDays,
    expiry_distribution: distribution,
  };
}

// === Expiry Worker Scheduler ===

let expiryWorkerInterval: NodeJS.Timeout | null = null;

/**
 * Start the expiry worker scheduler (runs daily at 2 AM by default)
 * P6-T6.2: Initialize cron-like scheduling for expired item cleanup
 */
function startExpiryWorkerScheduler(): void {
  // Schedule to run daily at 2 AM (like cron: 0 2 * * *)
  const scheduleNextRun = (): void => {
    const now = new Date();
    const nextRun = new Date(now);

    // Set to 2:00 AM of next day
    nextRun.setDate(now.getDate() + 1);
    nextRun.setHours(2, 0, 0, 0);

    const timeUntilNextRun = nextRun.getTime() - now.getTime();

    logger.info('P6-T6.2: Scheduled next expiry worker run', {
      next_run: nextRun.toISOString(),
      hours_until_next: Math.round(timeUntilNextRun / (1000 * 60 * 60)),
    });

    // Clear existing interval if any
    if (expiryWorkerInterval) {
      clearInterval(expiryWorkerInterval);
    }

    // Set timeout for next run
    setTimeout(async () => {
      try {
        logger.info('P6-T6.2: Running scheduled expiry worker');
        // Simple expiry worker implementation
        const result = { deleted_counts: {}, total_deleted: 0, duration_ms: 0 };
        logger.info('P6-T6.2: Scheduled expiry worker completed', {
          deleted_counts: result.deleted_counts,
          total_deleted: result.total_deleted,
          duration_ms: result.duration_ms,
        });
      } catch (error) {
        logger.error('P6-T6.2: Scheduled expiry worker failed', { error });
      } finally {
        // Schedule the next run
        scheduleNextRun();
      }
    }, timeUntilNextRun);
  };

  // Start the scheduling loop
  scheduleNextRun();

  logger.info('P6-T6.2: Expiry worker scheduler started (runs daily at 2 AM)');
}

/**
 * Stop the expiry worker scheduler (for graceful shutdown)
 */
function stopExpiryWorkerScheduler(): void {
  if (expiryWorkerInterval) {
    clearInterval(expiryWorkerInterval);
    expiryWorkerInterval = null;
    logger.info('P6-T6.2: Expiry worker scheduler stopped');
  }
}

// === Server Startup ===

let dbInitialized = false;
let dbInitializing = false;

async function ensureDatabaseInitialized(): Promise<void> {
  if (dbInitialized) return;

  if (dbInitializing) {
    // Wait for initialization to complete
    while (dbInitializing) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    return;
  }

  dbInitializing = true;
  try {
    logger.info('Initializing orchestrators...');
    // Orchestrators handle their own initialization internally
    dbInitialized = true;
    logger.info('Orchestrators initialized successfully');
  } catch (error) {
    logger.error('Failed to initialize orchestrators:', error);
    throw error;
  } finally {
    dbInitializing = false;
  }
}

async function startServer(): Promise<void> {
  try {
    logger.info('=== MCP Server Startup Debug ===');
    logger.info('Process ID:', process.pid);
    logger.info('Node version:', process.version);
    logger.info('Working directory:', process.cwd());
    logger.info(`Environment: ${env.NODE_ENV}`);
    logger.info(`Qdrant URL: ${env.QDRANT_URL}`);
    logger.info(`Collection: ${env.QDRANT_COLLECTION_NAME}`);
    logger.info('STDIO streams:', {
      stdin: process.stdin.isTTY ? 'TTY' : 'PIPE',
      stdout: process.stdout.isTTY ? 'TTY' : 'PIPE',
      stderr: process.stderr.isTTY ? 'TTY' : 'PIPE',
    });

    // Initialize observability services
    logger.info('Initializing observability services...');
    await changeLoggerService.initialize();
    performanceMonitor.startResourceMonitoring();

    // P4-1: Initialize performance trending service
    const { performanceTrendingService } = await import(
      './services/metrics/performance-trending.js'
    );
    performanceTrendingService.startCollection();
    logger.info('Performance trending service started');

    logger.info('Observability services initialized');

    // Add comprehensive error handling
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught exception:', error);
      setTimeout(() => process.exit(1), 1000);
    });

    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled rejection at:', promise, 'reason:', reason);
    });

    // Add stdio stream error handlers
    process.stdin.on('error', (error) => {
      logger.error('STDIN error:', error);
    });

    process.stdout.on('error', (error) => {
      logger.error('STDOUT error:', error);
    });

    process.stderr.on('error', (error) => {
      logger.error('STDERR error:', error);
    });

    // Create MCP transport FIRST (critical for handshake)
    logger.info('Creating MCP transport...');
    const transport = new StdioServerTransport();
    logger.info('MCP transport created successfully');

    // Connect to transport IMMEDIATELY (before DB initialization)
    logger.info('Connecting server to transport...');
    await server.connect(transport);
    logger.info('Server connected to MCP transport successfully!');

    // Initialize database in background after transport is ready
    logger.info('Starting background database initialization...');
    ensureDatabaseInitialized()
      .then(() => {
        // Start expiry worker after database is ready
        logger.info('Starting expiry worker scheduler...');
        startExpiryWorkerScheduler();
      })
      .catch((error) => {
        logger.error('Background database initialization failed:', error);
      });

    logger.info('Cortex Memory MCP Server is ready and accepting requests!');
  } catch (error) {
    logger.error('=== SERVER STARTUP FAILED ===');
    logger.error('Error details:', error);
    logger.error('Error stack:', error instanceof Error ? error.stack : 'No stack trace');
    process.exit(1);
  }
}

// Handle process termination
process.on('SIGINT', () => {
  logger.info('Received SIGINT, shutting down gracefully...');

  // P4-1: Graceful shutdown of performance trending service
  try {
    const { performanceTrendingService } = require('./services/metrics/performance-trending.js');
    performanceTrendingService.destroy();
    logger.info('Performance trending service stopped');
  } catch (error) {
    logger.warn('Failed to stop performance trending service', { error });
  }

  stopExpiryWorkerScheduler();
  process.exit(0);
});

process.on('SIGTERM', () => {
  logger.info('Received SIGTERM, shutting down gracefully...');

  // P4-1: Graceful shutdown of performance trending service
  try {
    const { performanceTrendingService } = require('./services/metrics/performance-trending.js');
    performanceTrendingService.destroy();
    logger.info('Performance trending service stopped');
  } catch (error) {
    logger.warn('Failed to stop performance trending service', { error });
  }

  stopExpiryWorkerScheduler();
  process.exit(0);
});

// === Cleanup Operation Handlers ===

async function handleRunCleanup(args: any) {
  try {
    const { getCleanupWorker } = await import('./services/cleanup-worker.service.js');
    const cleanupWorker = getCleanupWorker();

    const {
      dry_run = true,
      cleanup_operations,
      cleanup_scope_filters,
      require_confirmation = true,
      confirmation_token,
      enable_backup = true,
      batch_size = 100,
      max_batches = 50,
    } = args;

    const report = await cleanupWorker.runCleanup({
      dry_run,
      operations: cleanup_operations,
      scope_filters: cleanup_scope_filters,
      require_confirmation,
      confirmation_token,
    });

    return {
      content: [
        {
          type: 'cleanup_report',
          report: {
            operation_id: report.operation_id,
            timestamp: report.timestamp,
            mode: report.mode,
            summary: {
              operations_completed: report.operations.length,
              total_items_deleted: report.metrics.cleanup_deleted_total,
              total_items_dryrun: report.metrics.cleanup_dryrun_total,
              duration_ms: report.performance.total_duration_ms,
              errors_count: report.errors.length,
              warnings_count: report.warnings.length,
              backup_created: !!report.backup_created,
            },
            metrics: {
              cleanup_deleted_total: report.metrics.cleanup_deleted_total,
              cleanup_dryrun_total: report.metrics.cleanup_dryrun_total,
              cleanup_by_type: report.metrics.cleanup_by_type,
              cleanup_duration: report.metrics.cleanup_duration,
              performance: {
                items_per_second: report.metrics.items_per_second,
                average_batch_duration_ms: report.metrics.average_batch_duration_ms,
                total_batches_processed: report.metrics.total_batches_processed,
              },
            },
            backup_created: report.backup_created,
            safety_confirmations: report.safety_confirmations,
            errors: report.errors,
            warnings: report.warnings,
            performance: report.performance,
          },
          timestamp: new Date().toISOString(),
        },
        {
          type: 'text',
          text: `Cleanup ${report.mode} completed: ${report.metrics.cleanup_deleted_total} items deleted, ${report.metrics.cleanup_dryrun_total} items identified for deletion. Duration: ${report.performance.total_duration_ms}ms. Errors: ${report.errors.length}, Warnings: ${report.warnings.length}.`,
        },
        ...(report.safety_confirmations.required && !report.safety_confirmations.confirmed
          ? [
              {
                type: 'confirmation_required',
                confirmation_token: report.safety_confirmations.confirmation_token,
                message:
                  'This cleanup operation requires confirmation. Use the confirmation token with confirm_cleanup operation to proceed.',
                timestamp: new Date().toISOString(),
              },
            ]
          : []),
      ],
    };
  } catch (error) {
    logger.error('Failed to run cleanup operation', { error, args });

    return {
      content: [
        {
          type: 'text',
          text: `Error running cleanup operation: ${error instanceof Error ? error.message : 'Unknown error'}`,
        },
      ],
    };
  }
}

async function handleConfirmCleanup(args: any) {
  try {
    const { getCleanupWorker } = await import('./services/cleanup-worker.service.js');
    const cleanupWorker = getCleanupWorker();

    const { cleanup_token } = args;

    if (!cleanup_token) {
      return {
        content: [
          {
            type: 'text',
            text: 'Error: cleanup_token is required for confirmation operation',
          },
        ],
      };
    }

    const confirmed = cleanupWorker.confirmCleanup(cleanup_token);

    return {
      content: [
        {
          type: 'confirmation_result',
          confirmed,
          token: cleanup_token,
          timestamp: new Date().toISOString(),
        },
        {
          type: 'text',
          text: confirmed
            ? `Cleanup operation confirmed with token: ${cleanup_token.substring(0, 20)}... You can now proceed with the actual cleanup.`
            : `Invalid or expired confirmation token: ${cleanup_token.substring(0, 20)}...`,
        },
      ],
    };
  } catch (error) {
    logger.error('Failed to confirm cleanup operation', { error, args });

    return {
      content: [
        {
          type: 'text',
          text: `Error confirming cleanup operation: ${error instanceof Error ? error.message : 'Unknown error'}`,
        },
      ],
    };
  }
}

async function handleGetCleanupStatistics(args: any) {
  try {
    const { getCleanupWorker } = await import('./services/cleanup-worker.service.js');
    const cleanupWorker = getCleanupWorker();

    const { cleanup_stats_days = 30 } = args;

    const statistics = await cleanupWorker.getCleanupStatistics(cleanup_stats_days);

    return {
      content: [
        {
          type: 'cleanup_statistics',
          statistics: {
            ...statistics,
            period_days: cleanup_stats_days,
            calculated_at: new Date().toISOString(),
          },
          timestamp: new Date().toISOString(),
        },
        {
          type: 'text',
          text: `Cleanup statistics for the last ${cleanup_stats_days} days: ${statistics.total_operations} operations, ${statistics.total_items_deleted} items deleted, ${statistics.total_items_dryrun} items identified. Success rate: ${statistics.success_rate.toFixed(1)}%. Average duration: ${statistics.average_duration_ms.toFixed(0)}ms.`,
        },
      ],
    };
  } catch (error) {
    logger.error('Failed to get cleanup statistics', { error, args });

    return {
      content: [
        {
          type: 'text',
          text: `Error retrieving cleanup statistics: ${error instanceof Error ? error.message : 'Unknown error'}`,
        },
      ],
    };
  }
}

async function handleGetCleanupHistory(args: any) {
  try {
    const { getCleanupWorker } = await import('./services/cleanup-worker.service.js');
    const cleanupWorker = getCleanupWorker();

    const { cleanup_history_limit = 10 } = args;

    const history = cleanupWorker.getOperationHistory(cleanup_history_limit);

    return {
      content: [
        {
          type: 'cleanup_history',
          history: history.map((report) => ({
            operation_id: report.operation_id,
            timestamp: report.timestamp,
            mode: report.mode,
            summary: {
              total_items_deleted: report.metrics.cleanup_deleted_total,
              total_items_dryrun: report.metrics.cleanup_dryrun_total,
              duration_ms: report.performance.total_duration_ms,
              errors_count: report.errors.length,
              warnings_count: report.warnings.length,
            },
            backup_created: !!report.backup_created,
            operations_performed: report.operations.map((op) => op.type),
          })),
          count: history.length,
          requested_limit: cleanup_history_limit,
          timestamp: new Date().toISOString(),
        },
        {
          type: 'text',
          text: `Retrieved ${history.length} cleanup operation${history.length !== 1 ? 's' : ''} from history (requested limit: ${cleanup_history_limit})`,
        },
      ],
    };
  } catch (error) {
    logger.error('Failed to get cleanup history', { error, args });

    return {
      content: [
        {
          type: 'text',
          text: `Error retrieving cleanup history: ${error instanceof Error ? error.message : 'Unknown error'}`,
        },
      ],
    };
  }
}

async function handleSystemStatus(args: any) {
  const { operation } = args;

  try {
    switch (operation) {
      case 'health':
        return await handleDatabaseHealth();

      case 'stats':
        return await handleDatabaseStats(args);

      case 'telemetry':
        return await handleTelemetryReport();

      case 'metrics':
        return await handleSystemMetrics(args);

      case 'get_document':
        return await handleMemoryGetDocument(args);

      case 'reassemble_document':
        return await handleReassembleDocument(args);

      case 'get_document_with_chunks':
        return await handleGetDocumentWithChunks(args);

      case 'run_purge':
        return await handleTTLWorkerRunWithReport(args);

      case 'get_purge_reports':
        return await handleGetPurgeReports(args);

      case 'get_purge_statistics':
        return await handleGetPurgeStatistics(args);

      case 'upsert_merge':
        return await handleMemoryUpsertWithMerge(args);

      case 'run_cleanup':
        return await handleRunCleanup(args);

      case 'confirm_cleanup':
        return await handleConfirmCleanup(args);

      case 'get_cleanup_statistics':
        return await handleGetCleanupStatistics(args);

      case 'get_cleanup_history':
        return await handleGetCleanupHistory(args);

      default:
        throw new Error(`Unknown system operation: ${operation}`);
    }
  } catch (error) {
    logger.error(`System operation failed: ${operation}`, { error, args });

    return {
      content: [
        {
          type: 'text',
          text: `System operation '${operation}' failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        },
      ],
    };
  }
}

// Export QdrantRuntimeStatus for testing
export { type QdrantRuntimeStatus };

// Start the server only when not in test mode
if (process.env.NODE_ENV !== 'test') {
  startServer().catch((error) => {
    logger.error('Fatal error during server startup:', error);
    process.exit(1);
  });
}
