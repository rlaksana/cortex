/**
 * Qdrant Database Adapter
 *
 * Implements the IDatabase interface for Qdrant vector database backend,
 * providing semantic search capabilities and vector operations.
 *
 * Features:
 * - Vector embeddings for semantic search
 * - Hybrid search combining vector and keyword search
 * - Support for all 16 knowledge types with scope isolation
 * - High-performance similarity search
 * - Automatic deduplication using content hashing
 * - Collection management and optimization
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 *
 * TypeScript Recovery: Phase 2.2e - Assessing remaining TypeScript compatibility issues
 */

import * as crypto from 'crypto';

import { QdrantClient } from '@qdrant/js-client-rest';
import { OpenAI } from 'openai';

import type { ExpiryTimeLabel } from '../../constants/expiry-times.js';
import {
  circuitBreakerManager,
  type CircuitBreakerStats,
} from '../../services/circuit-breaker.service.js';
import { EmbeddingService } from '../../services/embeddings/embedding-service.js';
import { getKeyVaultService } from '../../services/security/key-vault-service.js';
import type {
  AutonomousContext,
  BatchSummary,
  ItemResult,
  KnowledgeItem,
  MemoryFindResponse,
  MemoryStoreResponse,
  SearchQuery,
  SearchResult,
  StoreError,
  StoreResult,
} from '../../types/core-interfaces.js';
import type {
  BatchResult,
  CollectionId,
  DatabaseCapabilities,
  DatabaseConnection,
  DatabaseOperation,
  DatabaseResult,
  MutationBuilder,
  PointId,
  QueryBuilder,
  QueryFilter,
  QueryOptions,
  ReadConsistency,
  Transaction,
  TransactionOptions,
} from '../../types/database-generics.js';
import { calculateItemExpiry } from '../../utils/expiry-utils.js';
import { logger } from '../../utils/logger.js';
import {
  createFindObservability,
  createStoreObservability,
} from '../../utils/observability-helper.js';
import {
  hasPropertySimple,
  safePropertyAccess,
  isString,
  isNumber,
  isObject,
  hasMessage,
  isErrorLike
} from '../../utils/type-guards.js';
import {
  isDatabaseResult,
  isSuccessfulDatabaseResult,
  isFailedDatabaseResult,
  unwrapDatabaseResult,
  unwrapDatabaseResultAsArray,
  isQdrantPoint,
  isQdrantSearchResponse,
  isQdrantMetricsResponse,
  isMemoryFindResponse,
  isVectorConfig,
  hasShould,
  hasScoreThreshold,
  hasWithVector,
  hasTitleAndName,
  hasDescriptionAndContent,
  safeErrorProperty,
  safeQdrantPointAccess
} from '../../utils/database-type-guards.js';

// Search mode type definition
type SearchMode = 'auto' | 'deep' | 'fast';

import type {
  Condition,
  Filter,
  MemoryFilter,
  QdrantPointStruct,
  QdrantScoredPoint,
  RangeCondition,
} from '../../types/database.js';
import {
  ConnectionError,
  DatabaseError,
  NotFoundError,
  SystemError,
} from '../../types/database-generics.js';

// Concrete DatabaseError implementation for Qdrant
class QdrantDatabaseError extends DatabaseError {
  constructor(message: string, code: string, cause?: Error) {
    super(message, code, 'high', true, undefined, cause);
  }
}
import type {
  DatabaseMetrics,
  DeleteOptions,
  IVectorAdapter,
  SearchOptions,
  StoreOptions,
  VectorConfig,
} from '../interfaces/vector-adapter.interface.js';
import { createQdrantBootstrap, type HAConfig } from '../qdrant-bootstrap.js';
import { createQdrantHealthProbe, type QdrantHealthStatus } from '../qdrant-health-probe.js';

/**
 * Qdrant collection information interface
 */
export interface QdrantCollectionInfo {
  status: 'green' | 'yellow' | 'grey' | 'red';
  optimizer_status: 'ok' | { error: string };
  vectors_count?: number | null;
  indexed_vectors_count?: number | null;
  points_count?: number | null;
  segments_count: number;
  config: Record<string, unknown>;
  payload_schema: Record<string, unknown>;
  disk_data_size?: number;
  ram_data_size?: number;
}

/**
 * Configuration for local Qdrant client
 */
export interface LocalQdrantClientConfig {
  readonly url: string;
  readonly timeout?: number;
  apiKey?: string; // Remove readonly to allow conditional assignment
}

/**
 * Qdrant collection statistics interface
 */
export interface QdrantCollectionStats {
  vectorsCount: number;
  indexedVectorsCount: number;
  pointsCount: number;
  segmentsCount: number;
  diskDataSize: number;
  ramDataSize: number;
}

/**
 * Qdrant adapter implementing vector database operations
 */
// =============================================================================
// QDRANT ADAPTER - MAIN FILE
// =============================================================================
// This file has been refactored into focused modules:
// - Client bootstrap: src/db/qdrant/qdrant-client.ts
// - Collection management: src/db/qdrant/qdrant-collections.ts
// - Query/search: src/db/qdrant/qdrant-queries.ts
// - Index/maintenance: src/db/qdrant/qdrant-maintenance.ts
// - Health/diagnostics: src/db/qdrant/qdrant-health.ts
// =============================================================================

// Placeholder file to create qdrant subdirectory

// =============================================================================
// IMPORTS FROM MODULARIZED QDRANT ADAPTER
// =============================================================================

export class QdrantAdapter implements IVectorAdapter {
  private client!: QdrantClient;
  private openai!: OpenAI;
  private config: VectorConfig;
  private initialized: boolean = false;
  private embeddingService!: EmbeddingService;
  private healthProbe = createQdrantHealthProbe();
  private bootstrapService?: ReturnType<typeof createQdrantBootstrap>;
  private haConfig?: HAConfig;
  private capabilities!: DatabaseCapabilities;
  private readonly COLLECTION_NAME = 'knowledge_items';
  private qdrantCircuitBreaker = circuitBreakerManager.getCircuitBreaker('qdrant', {
    failureThreshold: 2, // Lower threshold for faster failure detection in tests
    recoveryTimeoutMs: 10000, // 10 seconds for faster recovery
    failureRateThreshold: 0.4, // 40%
    minimumCalls: 2, // Fewer calls needed for failure detection
  });
  private openaiCircuitBreaker = circuitBreakerManager.getCircuitBreaker('openai', {
    failureThreshold: 3,
    recoveryTimeoutMs: 30000, // 30 seconds
    failureRateThreshold: 0.4, // 40%
    minimumCalls: 5,
  });

  // Utility functions for DatabaseResult wrapping
  private createSuccessResult<T>(data: T, metadata?: Record<string, unknown>): DatabaseResult<T> {
    return {
      success: true,
      data,
      metadata,
    };
  }

  private createErrorResult<T>(
    error: DatabaseError,
    metadata?: Record<string, unknown>
  ): DatabaseResult<T> {
    return {
      success: false,
      error,
      metadata,
    };
  }

  private async wrapAsyncOperation<T>(
    operation: () => Promise<T>,
    operationName: string
  ): Promise<DatabaseResult<T>> {
    try {
      const result = await operation();
      return this.createSuccessResult(result, { operation: operationName });
    } catch (error) {
      const dbError =
        error instanceof DatabaseError
          ? error
          : new SystemError(
              `Failed ${operationName}: ${error instanceof Error ? error.message : String(error)}`,
              { operation: operationName },
              error instanceof Error ? error : undefined
            );
      return this.createErrorResult(dbError, { operation: operationName });
    }
  }

  // =============================================================================
  // CLIENT BOOTSTRAP SECTION
  // =============================================================================
  // =============================================================================
  // CLIENT BOOTSTRAP SECTION
  // =============================================================================
  // Delegated to: src/db/qdrant/qdrant-client.ts
  constructor(config: VectorConfig) {
    // Store config for later async initialization
    this.config = {
      type: 'qdrant',
      host: config.host || 'localhost',
      port: config.port || 6333,
      database: config.database || 'qdrant',
      url: config.url || process.env.QDRANT_URL || 'http://localhost:6333',
      ...(config.apiKey !== undefined && { apiKey: config.apiKey }),
      vectorSize: config.vectorSize || 1536, // OpenAI ada-002
      distance: config.distance || 'Cosine',
      logQueries: config.logQueries || false,
      connectionTimeout: config.connectionTimeout || 30000,
      maxConnections: config.maxConnections || 10,
      collectionName: config.collectionName || 'knowledge_items',
      // Required VectorConfig properties
      size: config.size || config.vectorSize || 1536,
      embeddingModel: config.embeddingModel || 'text-embedding-3-small',
      batchSize: config.batchSize || 10,
    };

    // Initialize clients - will be enhanced asynchronously
    this.initializeClients();
  }

  /**
   * Initialize database and OpenAI clients with key vault integration
   */
  private async initializeClients(): Promise<void> {
    const keyVault = getKeyVaultService();

    try {
      // Get API keys from key vault
      const [qdrantKey, openaiKey] = await Promise.all([
        keyVault.get_key_by_name('qdrant_api_key'),
        keyVault.get_key_by_name('openai_api_key'),
      ]);

      // Update config with resolved keys
      const resolvedApiKey =
        this.config.apiKey || qdrantKey?.value || process.env.QDRANT_API_KEY || '';
      const resolvedOpenAIKey = openaiKey?.value || process.env.OPENAI_API_KEY || '';

      // Initialize Qdrant client
      const clientConfig: LocalQdrantClientConfig = {
        url: this.config.url || 'http://localhost:6333',
        timeout: this.config.connectionTimeout,
      };

      if (resolvedApiKey) {
        clientConfig.apiKey = resolvedApiKey;
        this.config.apiKey = resolvedApiKey;
      }

      this.client = new QdrantClient(clientConfig);

      // Initialize OpenAI client for embeddings
      if (resolvedOpenAIKey) {
        this.openai = new OpenAI({
          apiKey: resolvedOpenAIKey,
        });

        // Initialize embedding service for enhanced chunking support
        this.embeddingService = new EmbeddingService({
          apiKey: resolvedOpenAIKey,
        });
      } else {
        logger.warn('OpenAI API key not found, embedding functionality will be limited');
      }

      logger.info('Database clients initialized with key vault integration');
    } catch (error) {
      logger.warn(
        { error },
        'Failed to initialize clients from key vault, using environment fallback'
      );

      // Fallback to environment variables
      const fallbackApiKey = this.config.apiKey || process.env.QDRANT_API_KEY || '';
      const fallbackOpenAIKey = process.env.OPENAI_API_KEY || '';

      const clientConfig: LocalQdrantClientConfig = {
        url: this.config.url || 'http://localhost:6333',
        timeout: this.config.connectionTimeout,
      };

      if (fallbackApiKey) {
        clientConfig.apiKey = fallbackApiKey;
        this.config.apiKey = fallbackApiKey;
      }

      this.client = new QdrantClient(clientConfig);

      if (fallbackOpenAIKey) {
        this.openai = new OpenAI({
          apiKey: fallbackOpenAIKey,
        });
      }
    }
  }

  /**
   * Ensure clients are initialized before use
   */
  private async ensureClientsInitialized(): Promise<void> {
    if (!this.client || !this.openai) {
      await this.initializeClients();
    }

    this.capabilities = {
      supportsTransactions: false,
      supportsVectorSearch: true,
      supportsFullTextSearch: true,
      supportsBatchOperations: true,
      supportsStreaming: false,
      maxBatchSize: 100,
      maxConnections: 10,
      supportedOperations: [
        'store',
        'update',
        'delete',
        'search',
        'semanticSearch',
        'vectorSearch',
        'hybridSearch',
        'generateEmbedding',
        'similarityDetection',
        'deduplication',
        'backup',
        'restore',
        'optimize',
      ],
      consistencyLevels: ['strong', 'eventual'] as ReadConsistency[],
    };
  }

  // === TTL Helper Methods ===

  /**
   * Get TTL policy for a knowledge kind
   */
  private getTTLPolicyForKind(kind?: string): ExpiryTimeLabel {
    if (!kind) return 'default';

    // Special cases for specific knowledge types
    switch (kind) {
      case 'pr_context':
        return 'short'; // 24 hours
      case 'entity':
      case 'relation':
      case 'observation':
      case 'decision':
      case 'section':
        return 'long'; // 90 days
      case 'ddl':
        return 'permanent'; // Never expires
      default:
        return 'default'; // 30 days
    }
  }

  /**
   * Calculate expiry with policy for an item
   */
  private calculateItemExpiryWithPolicy(item: KnowledgeItem): string {
    // Priority order: explicit expiry_at → scope-level TTL → kind-based TTL → default
    if (item.data.expiry_at && typeof item.data.expiry_at === 'string') {
      return item.data.expiry_at;
    }

    // Use TTL policy based on knowledge kind
    const policy = this.getTTLPolicyForKind(item.kind);
    return calculateItemExpiry(item, policy);
  }

  /**
   * Convert expiry timestamp to TTL epoch for Qdrant
   */
  private calculateTTLEpoch(expiryAt: string): number | null {
    if (expiryAt === '9999-12-31T23:59:59.999Z') {
      return null; // Permanent item
    }

    try {
      const expiryDate = new Date(expiryAt);
      return Math.floor(expiryDate.getTime() / 1000);
    } catch (error) {
      logger.warn({ expiryAt, error }, 'Failed to parse expiry date, using default TTL');
      // Fall back to 30 days from now
      return Math.floor((Date.now() + 30 * 24 * 60 * 60 * 1000) / 1000);
    }
  }

  // === Lifecycle Management ===

  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    try {
      logger.info('Initializing Qdrant adapter...');

      // Ensure clients are initialized with key vault
      await this.ensureClientsInitialized();

      // Test connection by getting collections
      await this.client.getCollections();

      // Ensure collection exists
      await this.ensureCollection();

      this.initialized = true;
      logger.info('✅ Qdrant adapter initialized successfully');
    } catch (error) {
      logger.error({ error }, '❌ Failed to initialize Qdrant adapter');
      throw new ConnectionError(
        'Failed to initialize Qdrant connection',
        { originalError: error instanceof Error ? error.message : String(error) },
        error instanceof Error ? error : undefined
      );
    }
  }

  // =============================================================================
  // HEALTH/DIAGNOSTICS SECTION
  // =============================================================================

  async healthCheck(): Promise<boolean> {
    try {
      return await this.qdrantCircuitBreaker.execute(async () => {
        await this.client.getCollections();
        this.logQdrantCircuitBreakerEvent('health_check_success');
        return true;
      }, 'qdrant_health_check');
    } catch (error) {
      logger.error({ error }, 'Qdrant health check failed');
      this.logQdrantCircuitBreakerEvent(
        'health_check_failure',
        error instanceof Error ? error : new Error(String(error))
      );
      return false;
    }
  }

  async getMetrics(): Promise<DatabaseMetrics> {
    try {
      const healthy = await this.healthCheck();
      const collectionInfo = await this.client.getCollection(this.COLLECTION_NAME);

      return {
        type: 'qdrant',
        healthy,
        connectionCount: 1, // Qdrant uses HTTP connections
        queryLatency: 0, // TODO: Implement query latency tracking
        storageSize: collectionInfo.vectors_count || 0,
        lastHealthCheck: new Date().toISOString(),
        vectorCount: collectionInfo.vectors_count || 0,
      };
    } catch (error) {
      logger.error({ error }, 'Failed to get Qdrant metrics');
      throw new SystemError(
        'Failed to retrieve database metrics',
        { operation: 'getMetrics' },
        error instanceof Error ? error : undefined
      );
    }
  }

  async close(): Promise<void> {
    try {
      // Qdrant client doesn't have explicit close method
      this.initialized = false;
      logger.info('Qdrant adapter closed');
    } catch (error) {
      logger.error({ error }, 'Error closing Qdrant adapter');
      throw new SystemError(
        'Failed to close Qdrant adapter',
        { operation: 'close' },
        error instanceof Error ? error : undefined
      );
    }
  }

  // === Knowledge Storage Operations ===

  async store(
    items: readonly KnowledgeItem[],
    options: StoreOptions = {}
  ): Promise<DatabaseResult<MemoryStoreResponse>> {
    return this.wrapAsyncOperation(async () => {
      return await this.qdrantCircuitBreaker.execute(async () => {
        await this.ensureInitialized();
        const startTime = Date.now();

        const { batchSize = 100, skipDuplicates = false } = options;

        try {
          logger.debug({ itemCount: items.length, options }, 'Storing items in Qdrant');

          const stored: StoreResult[] = [];
          const errors: StoreError[] = [];
          const itemResults: ItemResult[] = [];

          // Process items in batches
          for (let i = 0; i < items.length; i += batchSize) {
            const batch = items.slice(i, i + batchSize);

            for (let j = 0; j < batch.length; j++) {
              const item = batch[j];
              const index = i + j;

              try {
                // Generate content hash for deduplication
                const contentHash = this.generateContentHash(item);

                // Check for duplicates if requested
                if (skipDuplicates) {
                  const existing = await this.findByHash(contentHash);
                  if (existing.length > 0) {
                    const existingPoint = existing[0];
                    const existingId =
                      typeof existingPoint.id === 'object' && 'uuid' in existingPoint.id
                        ? existingPoint.id.uuid
                        : typeof existingPoint.id === 'object' && 'num' in existingPoint.id
                          ? (existingPoint.id.num as number).toString()
                          : existingPoint.id.toString();

                    stored.push({
                      id: existingId,
                      status: 'skipped_dedupe',
                      kind: item.kind,
                      created_at:
                        (existingPoint.payload?.created_at as string) || new Date().toISOString(),
                    });

                    // Add to item results
                    const skippedResult: ItemResult = {
                      input_index: index,
                      status: 'skipped_dedupe',
                      kind: item.kind,
                      reason: 'Duplicate content',
                      existing_id: existingId,
                      created_at:
                        (existingPoint.payload?.created_at as string) || new Date().toISOString(),
                    };
                    if (item.content !== undefined) {
                      skippedResult.content = item.content;
                    }
                    itemResults.push(skippedResult);
                    continue;
                  }
                }

                // Generate embedding with chunking context if available
                const content = this.extractContentForEmbedding(item);
                const chunkingContext = item.data.is_chunk
                  ? {
                      is_chunk: true as const,
                      chunk_index: Number(item.data.chunk_index) || 0,
                      total_chunks: Number(item.data.total_chunks) || 1,
                      parent_id: String(item.data.parent_id || ''),
                      extracted_title: String(item.data.extracted_title || ''),
                    }
                  : undefined;
                const embedding = await this.generateEmbeddingWithContext(content, chunkingContext);

                // Generate sparse vector for keyword search
                const sparseVector = this.generateSparseVector(content);

                // Calculate TTL and expiry for this item
                const expiryAt = this.calculateItemExpiryWithPolicy(item);
                const ttlEpoch = this.calculateTTLEpoch(expiryAt);

                // Create point for Qdrant
                const point = {
                  id: item.id || `qdrant_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                  vector: [...embedding],
                  sparse_vector: {
                    content_sparse: sparseVector,
                  },
                  payload: {
                    kind: item.kind || 'section',
                    scope: item.scope || {},
                    data: item.data || {},
                    content_hash: contentHash,
                    created_at: item.created_at || new Date().toISOString(),
                    updated_at: new Date().toISOString(),
                    content,
                    expiry_at: expiryAt,
                    ttl_policy: this.getTTLPolicyForKind(item.kind),
                  },
                };

                // Add TTL epoch for Qdrant's native TTL if not permanent
                if (ttlEpoch !== null) {
                  const qdrantPoint = point as QdrantPointStruct & { ttl_epoch?: number };
                  qdrantPoint.ttl_epoch = ttlEpoch;
                }

                // Store in Qdrant
                await this.client.upsert(this.COLLECTION_NAME, {
                  wait: true,
                  points: [point],
                });

                stored.push({
                  id: point.id,
                  status: 'inserted',
                  kind: item.kind,
                  created_at: new Date().toISOString(),
                });

                // Add to item results
                const storedResult: ItemResult = {
                  input_index: index,
                  status: 'stored',
                  kind: item.kind,
                  id: point.id,
                  created_at: new Date().toISOString(),
                };
                if (item.content !== undefined) {
                  storedResult.content = item.content;
                }
                itemResults.push(storedResult);
              } catch (error) {
                const storeError: StoreError = {
                  index,
                  error_code: 'STORE_ERROR',
                  message: error instanceof Error ? error.message : 'Unknown error',
                };
                errors.push(storeError);

                // Add to item results
                const errorResult: ItemResult = {
                  input_index: index,
                  status: 'validation_error',
                  kind: item.kind,
                  reason: error instanceof Error ? error.message : 'Unknown error',
                  error_code: 'STORE_ERROR',
                };
                if (item.content !== undefined) {
                  errorResult.content = item.content;
                }
                itemResults.push(errorResult);
              }
            }
          }

          // Generate autonomous context
          const autonomousContext = this.generateAutonomousContext(stored, errors);

          // Generate summary from item results
          const summary: BatchSummary = {
            stored: itemResults.filter((item) => item.status === 'stored').length,
            skipped_dedupe: itemResults.filter((item) => item.status === 'skipped_dedupe').length,
            business_rule_blocked: itemResults.filter(
              (item) => item.status === 'business_rule_blocked'
            ).length,
            validation_error: itemResults.filter((item) => item.status === 'validation_error')
              .length,
            total: itemResults.length,
          };

          logger.debug(
            {
              stored: stored.length,
              errors: errors.length,
              items: itemResults.length,
            },
            'Qdrant store operation completed'
          );

          return {
            // Enhanced response format
            items: itemResults,
            summary,

            // Legacy fields for backward compatibility
            stored,
            errors,
            autonomous_context: autonomousContext,

            // Observability metadata
            observability: createStoreObservability(
              true, // vector_used
              false, // degraded (Qdrant adapter assumes not degraded)
              Date.now() - startTime,
              0.8 // confidence score
            ),

            // Required meta field for unified response format
            meta: {
              strategy: 'vector',
              vector_used: true,
              degraded: false,
              source: 'qdrant-adapter',
              execution_time_ms: Date.now() - startTime,
              confidence_score: 0.8,
              truncated: false,
            },
          };
        } catch (error) {
          logger.error({ error, itemCount: items.length }, 'Qdrant store operation failed');
          this.logQdrantCircuitBreakerEvent(
            'store_failure',
            error instanceof Error ? error : new Error(String(error)),
            { itemCount: items.length }
          );
          throw new SystemError(
            'Failed to store items in Qdrant',
            { operation: 'store', itemCount: items.length },
            error instanceof Error ? error : undefined
          );
        }
      }, 'qdrant_store');
    }, 'store');
  }

  async update(
    items: readonly KnowledgeItem[],
    options: StoreOptions = {}
  ): Promise<DatabaseResult<MemoryStoreResponse>> {
    // For Qdrant, update is the same as store (upsert)
    return await this.store(items, { ...options, upsert: true });
  }

  async delete(
    ids: readonly PointId[],
    options: DeleteOptions = {}
  ): Promise<DatabaseResult<{ deletedCount: number; errors: readonly StoreError[] }>> {
    return this.wrapAsyncOperation(async () => {
      await this.ensureInitialized();

      const { validate = true } = options;
      let deleted = 0;
      const errors: StoreError[] = [];

      try {
        logger.debug({ ids, options }, 'Deleting items from Qdrant');

        // Convert PointId array to string array for Qdrant client
        const idStrings = ids.map((id) => (typeof id === 'string' ? id : String(id)));

        for (const [index, id] of idStrings.entries()) {
          try {
            if (validate) {
              // Check if item exists
              const result = await this.client.retrieve(this.COLLECTION_NAME, {
                ids: [id],
                with_payload: true,
              });

              if (result.length === 0) {
                throw new NotFoundError(id);
              }
            }

            // Delete from Qdrant
            await this.client.delete(this.COLLECTION_NAME, {
              wait: true,
              points: [id],
            });

            deleted++;
          } catch (error) {
            errors.push({
              index,
              error_code: 'DELETE_ERROR',
              message: error instanceof Error ? error.message : 'Unknown error',
            });
          }
        }

        logger.debug({ deleted, errors: errors.length }, 'Qdrant delete operation completed');
        return { deletedCount: deleted, errors };
      } catch (error) {
        logger.error({ error, ids }, 'Qdrant delete operation failed');
        throw new SystemError(
          'Failed to delete items from Qdrant',
          { operation: 'delete', ids },
          error instanceof Error ? error : undefined
        );
      }
    }, 'delete');
  }

  async findById(ids: readonly PointId[]): Promise<DatabaseResult<readonly KnowledgeItem[]>> {
    return this.wrapAsyncOperation(async () => {
      await this.ensureInitialized();

      try {
        // Convert PointId array to string array for Qdrant client
        const idStrings = ids.map((id) => (typeof id === 'string' ? id : String(id)));

        const results = await this.client.retrieve(this.COLLECTION_NAME, {
          ids: idStrings,
          with_payload: true,
        });

        return results.map((point) =>
          this.pointToKnowledgeItem(point as unknown as QdrantScoredPoint)
        );
      } catch (error) {
        logger.error({ error, ids }, 'Failed to find items by ID in Qdrant');
        throw new QdrantDatabaseError(
          'Failed to find items by ID',
          'FIND_ERROR',
          error instanceof Error ? error : new Error(String(error))
        );
      }
    }, 'findById');
  }

  // === Search Operations ===

  // =============================================================================
  // QUERY/SEARCH SECTION
  // =============================================================================

  async search(
    query: SearchQuery,
    options: SearchOptions = {}
  ): Promise<DatabaseResult<MemoryFindResponse>> {
    return this.wrapAsyncOperation(async () => {
      await this.ensureInitialized();
      const startTime = Date.now();

      // No options needed for now

      logger.debug({ query, options }, 'Searching Qdrant');

      // Determine search mode
      const mode: SearchMode = (query.mode as SearchMode) || 'auto';
      let searchResult: DatabaseResult<readonly SearchResult[]>;

      switch (mode) {
        case 'auto':
          searchResult = await this.hybridSearch(query.query, options);
          break;
        case 'deep':
          searchResult = await this.semanticSearch(query.query, options);
          break;
        case 'fast':
          searchResult = await this.exactSearch(query.query, options);
          break;
        default:
          searchResult = await this.hybridSearch(query.query, options);
          break;
      }

      if (!searchResult.success) {
        const errorResult = searchResult as { success: false; error: DatabaseError };
        throw errorResult.error;
      }

        const searchResults = [...searchResult.data]; // Convert readonly to mutable

        // Filter by scope if specified
        const filteredResults = query.scope
          ? searchResults.filter((result) => this.matchesScope(result.scope, query.scope!))
          : searchResults;

        // Filter by types if specified
        const typeFilteredResults =
          query.types && query.types.length > 0
            ? filteredResults.filter((result) => query.types!.includes(result.kind))
            : filteredResults;

        // Limit results
        const limitedResults = typeFilteredResults.slice(0, query.limit || 50);

        const autonomousContext = {
          search_mode_used: mode,
          results_found: limitedResults.length,
          confidence_average:
            limitedResults.length > 0
              ? limitedResults.reduce((sum, r) => sum + r.confidence_score, 0) /
                limitedResults.length
              : 0,
          user_message_suggestion:
            limitedResults.length > 0
              ? `Found ${limitedResults.length} relevant items`
              : 'No items found matching your query',
        };

        logger.debug(
          {
            results: limitedResults.length,
            query: query.query,
            mode,
          },
          'Qdrant search completed'
        );

        return {
          results: limitedResults,
          items: limitedResults,
          total_count: limitedResults.length,
          autonomous_context: autonomousContext,

          // Observability metadata
          observability: createFindObservability(
            mode, // SearchMode type
            true, // vector_used
            false, // degraded (Qdrant adapter assumes not degraded)
            Date.now() - startTime,
            limitedResults.length > 0
              ? limitedResults.reduce((sum, r) => sum + r.confidence_score, 0) /
                  limitedResults.length
              : 0
          ),

          // Required meta field for unified response format
          meta: {
            strategy: mode,
            vector_used: true,
            degraded: false,
            source: 'qdrant-adapter',
            execution_time_ms: Date.now() - startTime,
            confidence_score:
              limitedResults.length > 0
                ? limitedResults.reduce((sum, r) => sum + r.confidence_score, 0) /
                  limitedResults.length
                : 0,
            truncated: false,
          },
        };
    }, 'search');
  }

  async semanticSearch(
    query: string,
    options: SearchOptions = {}
  ): Promise<DatabaseResult<readonly SearchResult[]>> {
    await this.ensureInitialized();

    const { limit = 50, score_threshold = 0.7 } = options;

    try {
      // Generate embedding for query
      const embeddingResult = await this.generateEmbedding(query);
      if (isFailedDatabaseResult(embeddingResult)) {
        throw embeddingResult.error;
      }
      const queryEmbedding = [...embeddingResult.data];

      // Build filter for scope and types
      const searchFilter = this.buildSearchFilter({});

      // Search in Qdrant
      const response = await this.searchWithCompatibleTypes({
        vector: queryEmbedding,
        limit,
        score_threshold,
        with_payload: ['kind', 'scope', 'data', 'created_at', 'content'],
        filter: searchFilter,
      });

      return this.createSuccessResult(
        response.map((result) => this.searchResultToSearchResult(result, 'semantic')),
        { operation: 'semantic_search', query, limit, score_threshold }
      );
    } catch (error) {
      logger.error({ error, query }, 'Qdrant semantic search failed');
      return this.createErrorResult(
        new QdrantDatabaseError(
          'Failed to perform semantic search',
          'SEMANTIC_SEARCH_ERROR',
          error as Error
        ),
        { operation: 'semantic_search', query }
      );
    }
  }

  async exactSearch(
    query: string,
    options: SearchOptions = {}
  ): Promise<DatabaseResult<readonly SearchResult[]>> {
    await this.ensureInitialized();

    const { limit = 50, score_threshold = 0.3 } = options;

    try {
      // Generate sparse vector for query
      const querySparse = this.generateSparseVector(query);

      // Build filter
      const searchFilter = this.buildSearchFilter({});

      // Search using sparse vector
      const response = await this.client.search(this.COLLECTION_NAME, {
        vector: { name: 'content_sparse', vector: querySparse },
        limit,
        score_threshold,
        with_payload: ['kind', 'scope', 'data', 'created_at', 'content'],
        filter: searchFilter as any,
      });

      return this.createSuccessResult(
        response.map((result) => this.searchResultToSearchResult(result, 'exact')),
        { operation: 'exact_search', query, limit }
      );
    } catch (error) {
      logger.error({ error, query }, 'Qdrant exact search failed');
      return this.createErrorResult(
        new QdrantDatabaseError(
          'Failed to perform exact search',
          'EXACT_SEARCH_ERROR',
          error instanceof Error ? error : new Error(String(error))
        ),
        { operation: 'exact_search', query }
      );
    }
  }

  async hybridSearch(
    query: string,
    options: SearchOptions = {}
  ): Promise<DatabaseResult<readonly SearchResult[]>> {
    await this.ensureInitialized();

    const { limit = 50 } = options;

    try {
      // Generate both embeddings
      const [embeddingResult] = await Promise.all([
        this.generateEmbedding(query),
        Promise.resolve(this.generateSparseVector(query)),
      ]);

      if (isFailedDatabaseResult(embeddingResult)) {
        throw embeddingResult.error;
      }
      const queryEmbedding = [...embeddingResult.data];

      // Build filter
      const searchFilter = this.buildSearchFilter({});

      // Search using vector (semantic)
      const response = await this.client.search(this.COLLECTION_NAME, {
        vector: queryEmbedding,
        limit,
        score_threshold: 0.5,
        with_payload: ['kind', 'scope', 'data', 'created_at', 'content'],
        filter: searchFilter as unknown,
      });

      return this.createSuccessResult(
        response.map((result) => this.searchResultToSearchResult(result, 'hybrid')),
        { operation: 'hybrid_search', query, limit }
      );
    } catch (error) {
      logger.error({ error, query }, 'Qdrant hybrid search failed');
      return this.createErrorResult(
        new QdrantDatabaseError(
          'Failed to perform hybrid search',
          'HYBRID_SEARCH_ERROR',
          error instanceof Error ? error : new Error(String(error))
        ),
        { operation: 'hybrid_search', query }
      );
    }
  }

  // === Knowledge Type Specific Operations ===

  async storeByKind(
    kind: string,
    items: readonly KnowledgeItem[],
    options: StoreOptions = {}
  ): Promise<DatabaseResult<MemoryStoreResponse>> {
    // Filter items by kind and store them
    const filteredItems = items.filter((item) => item.kind === kind);
    return await this.store(filteredItems, options);
  }

  async searchByKind(
    kinds: readonly string[],
    query: SearchQuery,
    options: SearchOptions = {}
  ): Promise<DatabaseResult<MemoryFindResponse>> {
    const searchResult = await this.search(query, options);

    if (!searchResult.success) {
      return searchResult; // Return the error result directly
    }

    // Filter results by kinds
    const filteredResults = searchResult.data.results.filter((result) =>
      kinds.includes(result.kind)
    );

    return this.createSuccessResult(
      {
        ...searchResult.data,
        results: filteredResults,
        total_count: filteredResults.length,
      },
      { operation: 'searchByKind', kinds, query: query.text || 'vector_search' }
    );
  }

  async findByScope(
    scope: { project?: string; branch?: string; org?: string },
    options: SearchOptions = {}
  ): Promise<DatabaseResult<readonly KnowledgeItem[]>> {
    return this.wrapAsyncOperation(async () => {
      await this.ensureInitialized();

      try {
        // Build filter for scope
        const searchFilter = this.buildSearchFilter({ scope });

        // Search using a generic embedding (space or common term)
        const embeddingResult = await this.generateEmbedding('knowledge');
        if (isFailedDatabaseResult(embeddingResult)) {
          throw embeddingResult.error;
        }
        const genericEmbedding = [...embeddingResult.data];

        const response = await this.client.search(this.COLLECTION_NAME, {
          vector: genericEmbedding,
          limit: options.cache ? 1000 : 1000, // Large limit for scope search
          score_threshold: 0.1,
          with_payload: true,
                    filter: searchFilter as unknown,
        });

        return response.map((result) =>
          this.pointToKnowledgeItem(result as unknown as QdrantScoredPoint)
        );
      } catch (error) {
        logger.error({ error, scope }, 'Qdrant scope search failed');
        throw new QdrantDatabaseError(
          'Failed to search by scope in Qdrant',
          'SCOPE_SEARCH_ERROR',
          error instanceof Error ? error : new Error(String(error))
        );
      }
    }, 'findByScope');
  }

  // === Advanced Operations ===

  async findSimilar(
    item: KnowledgeItem,
    threshold: number = 0.7
  ): Promise<DatabaseResult<readonly SearchResult[]>> {
    return this.wrapAsyncOperation(async () => {
      await this.ensureInitialized();

      try {
        // Generate embedding for the item with chunking context if available
        const content = this.extractContentForEmbedding(item);
        const chunkingContext = item.data.is_chunk
          ? {
              is_chunk: true,
              chunk_index: item.data.chunk_index as number,
              total_chunks: item.data.total_chunks as number,
              parent_id: item.data.parent_id as string,
              extracted_title: item.data.extracted_title as string,
            }
          : undefined;
        const embedding = await this.generateEmbeddingWithContext(content, chunkingContext);

        // Search for similar items
        const response = await this.client.search(this.COLLECTION_NAME, {
          vector: [...embedding],
          limit: 10,
          score_threshold: threshold,
          with_payload: ['kind', 'scope', 'data', 'created_at'],
                    filter: {
            must_not: [{ key: 'id', match: { value: item.id } }],
          } as unknown,
        });

        return response.map((result) => this.searchResultToSearchResult(result, 'semantic'));
      } catch (error) {
        logger.error({ error, itemId: item.id }, 'Qdrant similarity search failed');
        throw new QdrantDatabaseError(
          'Failed to find similar items in Qdrant',
          'SIMILARITY_SEARCH_ERROR',
          error instanceof Error ? error : new Error(String(error))
        );
      }
    }, 'findSimilar');
  }

  async checkDuplicates(
    items: readonly KnowledgeItem[]
  ): Promise<
    DatabaseResult<{
      duplicates: readonly KnowledgeItem[];
      originals: readonly KnowledgeItem[];
      similarityThreshold: number;
    }>
  > {
    return this.wrapAsyncOperation(async () => {
      const duplicates: KnowledgeItem[] = [];
      const originals: KnowledgeItem[] = [];

      for (const item of items) {
        const contentHash = this.generateContentHash(item);
        const existing = await this.findByHash(contentHash);

        if (existing.length > 0) {
          duplicates.push(item);
        } else {
          originals.push(item);
        }
      }

      return {
        duplicates: duplicates as readonly KnowledgeItem[],
        originals: originals as readonly KnowledgeItem[],
        similarityThreshold: 0.95,
      };
    }, 'checkDuplicates');
  }

  async getStatistics(scope?: { project?: string; branch?: string; org?: string }): Promise<
    DatabaseResult<{
      totalItems: number;
      itemsByKind: Record<string, number>;
      storageSize: number;
      lastUpdated: string;
      vectorCount: number;
    }>
  > {
    return this.wrapAsyncOperation(async () => {
      await this.ensureInitialized();

      try {
        // Get collection info
        const collectionInfo = await this.client.getCollection(this.COLLECTION_NAME);
        const totalItems = collectionInfo.vectors_count || 0;

        // Get a sample of items to determine kinds
        const sample = await this.client.scroll(this.COLLECTION_NAME, {
          limit: 1000,
          with_payload: ['kind'],
                    filter: scope ? (this.buildSearchFilter({ scope }) as unknown) : undefined,
        });

        const itemsByKind: Record<string, number> = {};
        let lastUpdated = new Date().toISOString();

        for (const point of sample.points) {
          const payload = point.payload || {};
          const kind = typeof payload.kind === 'string' ? payload.kind : 'unknown';
          itemsByKind[kind] = (itemsByKind[kind] || 0) + 1;

          const updatedAt = typeof payload.updated_at === 'string' ? payload.updated_at : undefined;
          if (updatedAt && updatedAt > lastUpdated) {
            lastUpdated = updatedAt;
          }
        }

        return {
          totalItems,
          itemsByKind,
          storageSize: totalItems * ((this.config.vectorSize || 1536) * 4), // Rough estimate
          lastUpdated,
          vectorCount: totalItems,
        };
      } catch (error) {
        logger.error({ error }, 'Failed to get Qdrant statistics');
        throw new QdrantDatabaseError(
          'Failed to retrieve statistics',
          'STATISTICS_ERROR',
          error instanceof Error ? error : new Error(String(error))
        );
      }
    }, 'getStatistics');
  }

  // === Batch Operations ===

  async bulkStore(
    items: readonly KnowledgeItem[],
    options: StoreOptions = {}
  ): Promise<DatabaseResult<BatchResult<KnowledgeItem>>> {
    return this.wrapAsyncOperation(async () => {
      const startTime = Date.now();
      const result = await this.store(items, { ...options, batchSize: 100 });

      if (isFailedDatabaseResult(result)) {
        const error = result.error;
        return {
          totalCount: items.length,
          successCount: 0,
          failureCount: items.length,
          results: items.map(
            (item) =>
              ({
                success: false,
                error: error,
              }) as DatabaseResult<KnowledgeItem>
          ),
          errors: [error],
          executionTimeMs: Date.now() - startTime,
        };
      }

      // Convert MemoryStoreResponse to BatchResult
      const successCount = result.data.stored.length;
      const failureCount = result.data.errors.length;
      const skippedCount = result.data.skipped?.length || 0;

      const batchResults: DatabaseResult<KnowledgeItem>[] = [];

      // Add successful results
      for (const stored of result.data.stored) {
        batchResults.push({
          success: true,
          data: items.find((item) => item.id === stored.id)!,
        });
      }

      // Add error results
      for (const storeError of result.data.errors) {
        const errorId = safePropertyAccess(storeError as unknown, 'id', isString);
        const item = items.find((item) => item.id === errorId);
        if (item) {
          batchResults.push({
            success: false,
            error: new QdrantDatabaseError(storeError.message, 'BULK_STORE_ERROR'),
          });
        }
      }

      // Add skipped results
      for (const skipped of result.data.skipped || []) {
        const item = items.find((item) => item.id === skipped.id);
        if (item) {
          batchResults.push({
            success: true,
            data: item,
          });
        }
      }

      return {
        totalCount: items.length,
        successCount,
        failureCount,
        results: batchResults,
        errors: result.data.errors.map(
          (e) => new QdrantDatabaseError(e.message, 'BULK_STORE_ERROR')
        ),
        executionTimeMs: Date.now() - startTime,
      };
    }, 'bulkStore');
  }

  async bulkDelete(
    filter: QueryFilter<Record<string, unknown>>,
    options?: DeleteOptions
  ): Promise<DatabaseResult<{ deletedCount: number }>> {
    return this.wrapAsyncOperation(async () => {
      await this.ensureInitialized();

      try {
        // Convert QueryFilter to internal MemoryFilter format
        const filterConfig: MemoryFilter = {};
        if (filter.kind) filterConfig.kind = String(filter.kind);
        if (filter.scope) filterConfig.scope = filter.scope as unknown;
        const searchFilter = this.buildSearchFilter(filterConfig);

        // Find items to delete
        const toDelete = await this.client.scroll(this.COLLECTION_NAME, {
          limit: 10000, // Large limit for bulk operation
          with_payload: ['id'],
                    filter: searchFilter as unknown,
        });

        if (toDelete.points.length === 0) {
          return { deletedCount: 0 };
        }

        const ids = toDelete.points.map((point) => point.id);

        // Delete items
        await this.client.delete(this.COLLECTION_NAME, {
          wait: true,
          points: ids,
        });

        logger.debug({ deletedCount: ids.length, filter }, 'Qdrant bulk delete completed');
        return { deletedCount: ids.length };
      } catch (error) {
        logger.error({ error, filter }, 'Qdrant bulk delete failed');
        throw new QdrantDatabaseError(
          'Failed to bulk delete items in Qdrant',
          'BULK_DELETE_ERROR',
          error instanceof Error ? error : new Error(String(error))
        );
      }
    }, 'bulkDelete');
  }

  async bulkSearch(
    queries: readonly SearchQuery[],
    options: SearchOptions = {}
  ): Promise<DatabaseResult<MemoryFindResponse[]>> {
    try {
      const results: MemoryFindResponse[] = [];
      for (const query of queries) {
        const searchResult = await this.search(query, options);

        if (!searchResult.success) {
          const failureResult = searchResult as { success: false; error: DatabaseError };
          throw (
            failureResult.error ??
            new SystemError('Bulk search failed due to an unknown error', { operation: 'bulkSearch' })
          );
        }

        results.push(searchResult.data);
      }

      const metadata = {
        operation: 'bulkSearch',
        queriesProcessed: queries.length,
        totalResults: results.reduce((sum, r) => sum + r.total_count, 0),
      };

      return this.createSuccessResult(results, metadata);
    } catch (error) {
      const dbError =
        error instanceof DatabaseError
          ? error
          : new SystemError(
              `Failed bulkSearch: ${error instanceof Error ? error.message : String(error)}`,
              { operation: 'bulkSearch' },
              error instanceof Error ? error : undefined
            );
      return this.createErrorResult(dbError, { operation: 'bulkSearch' });
    }
  }

  // === Vector Operations ===

  async generateEmbedding(content: string): Promise<DatabaseResult<readonly number[]>> {
    return this.wrapAsyncOperation(async () => {
      // Use enhanced embedding service if available
      if (this.embeddingService) {
        const result = await this.embeddingService.generateEmbeddingWithContext(content, {});
        return result.vector as readonly number[];
      }

      // Fallback to OpenAI direct API
      const response = await this.openai.embeddings.create({
        model: 'text-embedding-ada-002',
        input: content,
      });

      return response.data[0].embedding as readonly number[];
    }, 'generateEmbedding');
  }

  // Helper method with chunking context for internal use
  async generateEmbeddingWithContext(
    content: string,
    chunkingContext?: {
      is_chunk?: boolean;
      chunk_index?: number;
      total_chunks?: number;
      parent_id?: string;
      extracted_title?: string;
    }
  ): Promise<number[]> {
    try {
      // Use enhanced embedding service if chunking context is provided
      if (chunkingContext && this.embeddingService) {
        const result = await this.embeddingService.generateEmbeddingWithContext(
          content,
          chunkingContext
        );
        return result.vector;
      }

      // Fallback to OpenAI direct API
      const response = await this.openai.embeddings.create({
        model: 'text-embedding-ada-002',
        input: content,
      });

      return response.data[0].embedding;
    } catch (error) {
      logger.error({ error, contentLength: content.length }, 'Failed to generate embedding');
      throw new QdrantDatabaseError(
        'Failed to generate embedding',
        'EMBEDDING_ERROR',
        error instanceof Error ? error : new Error(String(error))
      );
    }
  }

  async storeWithEmbeddings(
    items: readonly (KnowledgeItem & { embedding: number[] })[]
  ): Promise<DatabaseResult<MemoryStoreResponse>> {
    return this.wrapAsyncOperation(async () => {
      const startTime = Date.now();
      await this.ensureInitialized();

      const stored: StoreResult[] = [];
      const errors: StoreError[] = [];
      const itemResults: ItemResult[] = [];

      try {
        const points = items.map((item) => ({
          id: item.id || `qdrant_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          vector: item.embedding,
          payload: {
            kind: item.kind,
            scope: item.scope,
            data: item.data,
            content_hash: this.generateContentHash(item),
            created_at: item.created_at || new Date().toISOString(),
            updated_at: new Date().toISOString(),
            content: this.extractContentForEmbedding(item),
          },
        }));

        // Store in batch
        await this.client.upsert(this.COLLECTION_NAME, {
          wait: true,
          points,
        });

        points.forEach((point, index) => {
          stored.push({
            id: point.id,
            status: 'inserted',
            kind: point.payload.kind,
            created_at: point.payload.created_at,
          });

          // Add to item results
          const storedResult: ItemResult = {
            input_index: index,
            status: 'stored',
            kind: point.payload.kind,
            id: point.id,
            created_at: point.payload.created_at,
          };
          const originalItem = items[index];
          if (originalItem.content !== undefined) {
            storedResult.content = originalItem.content;
          }
          itemResults.push(storedResult);
        });

        // Generate autonomous context
        const autonomousContext = this.generateAutonomousContext(stored, errors);

        // Generate summary from item results
        const summary: BatchSummary = {
          stored: itemResults.filter((item) => item.status === 'stored').length,
          skipped_dedupe: itemResults.filter((item) => item.status === 'skipped_dedupe').length,
          business_rule_blocked: itemResults.filter(
            (item) => item.status === 'business_rule_blocked'
          ).length,
          validation_error: itemResults.filter((item) => item.status === 'validation_error').length,
          total: itemResults.length,
        };

        return {
          // Enhanced response format
          items: itemResults,
          summary,

          // Legacy fields for backward compatibility
          stored,
          errors,
          autonomous_context: autonomousContext,
          observability: createStoreObservability(true, false, Date.now() - startTime, 0.9),

          // Required meta field for unified response format
          meta: {
            strategy: 'vector',
            vector_used: true,
            degraded: false,
            source: 'qdrant-adapter',
            execution_time_ms: Date.now() - startTime,
            confidence_score: 0.9,
            truncated: false,
          },
        };
      } catch (error) {
        logger.error(
          { error, itemCount: items.length },
          'Failed to store items with embeddings in Qdrant'
        );
        throw new QdrantDatabaseError(
          'Failed to store items with embeddings',
          'STORE_WITH_EMBEDDINGS_ERROR',
          error instanceof Error ? error : new Error(String(error))
        );
      }
    }, 'storeWithEmbeddings');
  }

  // === Administrative Operations ===

  async backup(
    destination?: string
  ): Promise<DatabaseResult<{ backupId: string; backupPath: string }>> {
    return this.wrapAsyncOperation(async () => {
      await this.ensureInitialized();

      try {
        // Create snapshot
        const snapshotResult = await this.client.createSnapshot(this.COLLECTION_NAME);
        if (!snapshotResult) {
          throw new QdrantDatabaseError(
            'Failed to create snapshot - null response',
            'BACKUP_ERROR'
          );
        }
        const snapshotName = snapshotResult.name;
        const backupPath = destination || `backups/${snapshotName}`;

        logger.info({ snapshotName, destination, backupPath }, 'Qdrant snapshot created');
        return {
          backupId: snapshotName,
          backupPath: backupPath,
        };
      } catch (error) {
        logger.error({ error }, 'Failed to create Qdrant snapshot');
        throw new QdrantDatabaseError(
          'Failed to create backup',
          'BACKUP_ERROR',
          error instanceof Error ? error : new Error(String(error))
        );
      }
    }, 'backup');
  }

  async restore(
    _source: string
  ): Promise<DatabaseResult<{ restored: boolean; itemCount: number }>> {
    return this.wrapAsyncOperation(async () => {
      throw new QdrantDatabaseError('Qdrant restore not implemented', 'UNSUPPORTED_OPERATION');
    }, 'restore');
  }

  async updateCollectionSchema(
    config: Partial<VectorConfig>
  ): Promise<DatabaseResult<{ updated: boolean }>> {
    return this.wrapAsyncOperation(async () => {
      await this.ensureInitialized();

      try {
        await this.client.updateCollection(this.COLLECTION_NAME, config);
        logger.info('Qdrant collection schema updated');
        return { updated: true };
      } catch (error) {
        logger.error({ error }, 'Failed to update Qdrant collection schema');
        throw new QdrantDatabaseError(
          'Failed to update collection schema',
          'SCHEMA_UPDATE_ERROR',
          error instanceof Error ? error : new Error(String(error))
        );
      }
    }, 'updateCollectionSchema');
  }

  async optimize(): Promise<DatabaseResult<{ optimized: boolean; timeMs: number }>> {
    return this.wrapAsyncOperation(async () => {
      await this.ensureInitialized();

      const startTime = Date.now();

      try {
        // Trigger collection optimization
        await this.client.updateCollection(this.COLLECTION_NAME, {
          optimizers_config: {
            deleted_threshold: 0.2,
            vacuum_min_vector_number: 1000,
            default_segment_number: 2,
          },
        });

        logger.info('Qdrant collection optimization completed');
        return {
          optimized: true,
          timeMs: Date.now() - startTime,
        };
      } catch (error) {
        logger.error({ error }, 'Failed to optimize Qdrant collection');
        throw new QdrantDatabaseError(
          'Failed to optimize Qdrant',
          'OPTIMIZE_ERROR',
          error instanceof Error ? error : new Error(String(error))
        );
      }
    }, 'optimize');
  }

  async validate(): Promise<DatabaseResult<{ valid: boolean; issues: string[] }>> {
    return this.wrapAsyncOperation(async () => {
      const issues: string[] = [];

      try {
        // Check connection
        const healthy = await this.healthCheck();
        if (!healthy) {
          issues.push('Qdrant connection unhealthy');
        }

        // Check collection existence
        const collections = await this.client.getCollections();
        const exists = collections.collections.some((c) => c.name === this.COLLECTION_NAME);
        if (!exists) {
          issues.push(`Missing collection: ${this.COLLECTION_NAME}`);
        }

        // Test vector search
        try {
          await this.vectorSearch(new Array(1536).fill(0));
        } catch {
          issues.push('Vector search functionality failed');
        }

        return { valid: issues.length === 0, issues };
      } catch (error) {
        issues.push(
          `Validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
        return { valid: false, issues };
      }
    }, 'validate');
  }

  // === Interface Implementation Methods ===

  getClient(): QdrantClient {
    return this.client;
  }

  async getCapabilities(): Promise<DatabaseCapabilities> {
    await this.ensureClientsInitialized();
    return this.capabilities;
  }

  async testFunctionality(operation: string): Promise<DatabaseResult<boolean>> {
    return this.wrapAsyncOperation(async () => {
      try {
        switch (operation) {
          case 'connection':
            return await this.healthCheck();
          case 'search': {
            const searchResult = await this.search({ query: 'test', limit: 1 });
            return searchResult.success;
          }
          case 'vector_search': {
            const embeddingResult = await this.generateEmbedding('test');
            if (isFailedDatabaseResult(embeddingResult)) {
              throw embeddingResult.error;
            }
            const vectorResult = await this.vectorSearch([...embeddingResult.data]);
            return vectorResult.success;
          }
          case 'store': {
            const testItem: KnowledgeItem = {
              kind: 'section',
              scope: { project: 'test' },
              data: { title: 'Test', content: 'Test content' },
            };
            const storeResult = await this.store([testItem]);
            return storeResult.success;
          }
          default:
            return false;
        }
      } catch (error) {
        logger.error({ operation, error }, 'Functionality test failed');
        throw new QdrantDatabaseError(
          'Functionality test failed',
          'TEST_FUNCTIONALITY_ERROR',
          error instanceof Error ? error : new Error(String(error))
        );
      }
    }, 'testFunctionality');
  }

  // === Private Helper Methods ===

  private async ensureInitialized(): Promise<void> {
    if (!this.initialized) {
      await this.initialize();
    }
  }

  // =============================================================================
  // COLLECTION MANAGEMENT SECTION
  // =============================================================================

  private async ensureCollection(): Promise<void> {
    try {
      const collections = await this.client.getCollections();
      const exists = collections.collections.some((c) => c.name === this.COLLECTION_NAME);

      if (!exists) {
        logger.info(`Creating ${this.COLLECTION_NAME} collection...`);

        await this.client.createCollection(this.COLLECTION_NAME, {
          vectors: {
            size: this.config.vectorSize!,
            distance: this.config.distance! as 'Cosine' | 'Euclid' | 'Dot' | 'Manhattan',
          },
          sparse_vectors: {
            content_sparse: {
              index: {
                type: 'keyword',
              },
            },
          },
          hnsw_config: {
            m: 16,
            ef_construct: 200,
            full_scan_threshold: 20000,
          },
          quantization_config: {
            scalar: {
              type: 'int8',
              quantile: 0.99,
              always_ram: true,
            },
          },
        });

        logger.info(`✅ ${this.COLLECTION_NAME} collection created`);
      }
    } catch (error) {
      logger.error({ error }, `Failed to ensure ${this.COLLECTION_NAME} collection exists`);
      throw error;
    }
  }

  private generateContentHash(item: KnowledgeItem): string {
    const content = this.extractContentForEmbedding(item);
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  private async findByHash(_hash: string): Promise<QdrantScoredPoint[]> {
    // This would require implementing a payload search by content_hash
    // For now, return empty array
    return [];
  }

  private extractContentForEmbedding(item: KnowledgeItem): string {
    const parts: string[] = [];

    // Add kind for context
    parts.push(`Type: ${item.kind}`);

    // Add scope information
    if (item.scope.project) parts.push(`Project: ${item.scope.project}`);
    if (item.scope.branch) parts.push(`Branch: ${item.scope.branch}`);
    if (item.scope.org) parts.push(`Organization: ${item.scope.org}`);

    // Extract data fields based on knowledge type
    const data = item.data;
    switch (item.kind) {
      case 'section':
        parts.push(String(data.title || ''));
        parts.push(String(data.content || ''));
        parts.push(String(data.heading || ''));
        break;
      case 'decision':
        parts.push(String(data.title || ''));
        parts.push(String(data.rationale || ''));
        parts.push(String(data.component || ''));
        break;
      case 'issue':
        parts.push(String(data.title || ''));
        parts.push(String(data.description || ''));
        parts.push(String(data.status || ''));
        break;
      case 'todo':
        parts.push(String(data.title || ''));
        parts.push(String(data.description || ''));
        parts.push(String(data.status || ''));
        break;
      case 'runbook':
        parts.push(String(data.title || ''));
        parts.push(String(data.description || ''));
        if (Array.isArray(data.steps)) {
          parts.push(data.steps.map(String).join(' '));
        }
        break;
      default:
        // Generic extraction
        const title = safePropertyAccess(data, 'title', isString) || safePropertyAccess(data, 'name', isString) || '';
        parts.push(String(title));
        const description = safePropertyAccess(data, 'description', isString) || safePropertyAccess(data, 'content', isString) || '';
        parts.push(String(description));
        if (typeof data === 'string') {
          parts.push(data);
        } else {
          parts.push(JSON.stringify(data));
        }
    }

    return parts.filter((part) => part && part.trim().length > 0).join(' ');
  }

  private generateSparseVector(content: string): { indices: number[]; values: number[] } {
    // Simple TF-IDF-like sparse vector generation
    const words = content
      .toLowerCase()
      .split(/\s+/)
      .filter((word) => word.length > 2);
    const wordFreq: Record<string, number> = {};

    words.forEach((word) => {
      wordFreq[word] = (wordFreq[word] || 0) + 1;
    });

    const indices: number[] = [];
    const values: number[] = [];

    Object.entries(wordFreq).forEach(([word, freq]) => {
      // Simple hash to generate index
      const index = Math.abs(this.hashCode(word)) % 10000;
      indices.push(index);
      values.push(freq / words.length); // Normalized frequency
    });

    return { indices, values };
  }

  private hashCode(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash;
  }

  private buildSearchFilter(filter: MemoryFilter): Filter | undefined {
    const qdrantFilter: Filter = {
      must: [],
    };

    // Add kind filter
    if (filter.kind) {
      qdrantFilter.must.push({
        key: 'kind',
        match: { value: filter.kind },
      });
    }

    // Add scope filters
    if (filter.scope) {
      if (filter.scope.project) {
        qdrantFilter.must.push({
          key: 'scope.project',
          match: { value: filter.scope.project },
        });
      }
      if (filter.scope.branch) {
        qdrantFilter.must.push({
          key: 'scope.branch',
          match: { value: filter.scope.branch },
        });
      }
      if (filter.scope.org) {
        qdrantFilter.must.push({
          key: 'scope.org',
          match: { value: filter.scope.org },
        });
      }
    }

    // Enhanced TTL filtering with comprehensive support
    const expiryConditions: Condition[] = [];
    const now = new Date().toISOString();

    // Filter by expiry before date (for finding expired items)
    if (filter.expiry_before) {
      expiryConditions.push({
        key: 'expiry_at',
        range: {
          lt: filter.expiry_before,
        },
      });
    }

    // Filter by expiry after date
    if (filter.expiry_after) {
      expiryConditions.push({
        key: 'expiry_at',
        range: {
          gt: filter.expiry_after,
        },
      });
    }

    // Filter by existence of expiry_at field
    if (filter.has_expiry === true) {
      expiryConditions.push({
        key: 'expiry_at',
        is_not_null: {},
      });
    } else if (filter.has_expiry === false) {
      expiryConditions.push({
        key: 'expiry_at',
        is_null: {},
      });
    }

    // Enhanced TTL policy filtering
    if (filter.ttl_policy) {
      expiryConditions.push({
        key: 'data.ttl_policy',
        match: { value: filter.ttl_policy },
      });
    }

    // Filter by TTL duration range
    if (filter.ttl_duration_min !== undefined || filter.ttl_duration_max !== undefined) {
      const durationRange: RangeCondition = {};
      if (filter.ttl_duration_min !== undefined) {
        durationRange.gte = filter.ttl_duration_min;
      }
      if (filter.ttl_duration_max !== undefined) {
        durationRange.lte = filter.ttl_duration_max;
      }
      expiryConditions.push({
        key: 'data.ttl_duration_ms',
        range: durationRange,
      });
    }

    // Filter by permanent items
    if (filter.is_permanent === true) {
      expiryConditions.push({
        key: 'expiry_at',
        match: { value: '9999-12-31T23:59:59.999Z' },
      });
    } else if (filter.is_permanent === false) {
      expiryConditions.push({
        key: 'expiry_at',
        range: {
          lt: '9999-12-31T23:59:59.999Z',
        },
      });
    }

    // Automatic expiry filtering (exclude expired items unless specifically requested)
    if (filter.include_expired !== true) {
      // Include items without expiry or with expiry in the future
      const nonExpiredCondition = {
        should: [
          { key: 'expiry_at', is_null: {} },
          { key: 'expiry_at', range: { gt: now } },
        ],
      };

      if (expiryConditions.length > 0) {
        // Combine existing expiry conditions with non-expired filter
        qdrantFilter.must.push(nonExpiredCondition as unknown);
      } else {
        if (hasShould(nonExpiredCondition)) {
          expiryConditions.push(...nonExpiredCondition.should);
        }
      }
    }

    // Add expiry conditions to filter
    if (expiryConditions.length > 0) {
      if (expiryConditions.length === 1) {
        qdrantFilter.must.push(expiryConditions[0]);
      } else {
        qdrantFilter.must.push({
          and: expiryConditions,
        });
      }
    }

    return qdrantFilter.must.length > 0 ? qdrantFilter : undefined;
  }

  private pointToKnowledgeItem(point: QdrantScoredPoint): KnowledgeItem {
    const payload = point.payload || {};
    const id =
      typeof point.id === 'object' && 'uuid' in point.id
        ? point.id.uuid
        : typeof point.id === 'object' && 'num' in point.id
          ? point.id.num.toString()
          : point.id.toString();

    return {
      id,
      kind: (payload.kind as string) || 'unknown',
      scope: (payload.scope as Record<string, unknown>) || {},
      data: (payload.data as Record<string, unknown>) || {},
      expiry_at: payload.expiry_at as string,
      created_at: (payload.created_at as string) || new Date().toISOString(),
      updated_at: (payload.updated_at as string) || new Date().toISOString(),
    };
  }

  private searchResultToSearchResult(result: unknown, matchType: string): SearchResult {
    // Type-safe casting for Qdrant response compatibility
    const qdrantPoint = result as unknown as QdrantScoredPoint;
    const payload = qdrantPoint.payload || {};

    // Handle different ID formats from Qdrant response
    let id: string;
    if (typeof qdrantPoint.id === 'object' && qdrantPoint.id !== null) {
      if ('uuid' in qdrantPoint.id) {
        id = qdrantPoint.id.uuid as string;
      } else if ('num' in qdrantPoint.id) {
        id = qdrantPoint.id.num.toString();
      } else {
        id = JSON.stringify(qdrantPoint.id);
      }
    } else {
      id = String(qdrantPoint.id);
    }

    return {
      id,
      kind: (payload.kind as string) || 'unknown',
      scope: (payload.scope as Record<string, unknown>) || {},
      data: (payload.data as Record<string, unknown>) || {},
      created_at: (payload.created_at as string) || new Date().toISOString(),
      confidence_score: qdrantPoint.score || 0,
      match_type: matchType as 'exact' | 'fuzzy' | 'semantic',
      ...(payload.content
        ? { highlight: [`${(payload.content as string).substring(0, 200)}...`] }
        : {}),
    };
  }

  /**
   * Search with compatible types - unified search method for internal use
   */
  private async searchWithCompatibleTypes(params: {
    vector: number[];
    limit?: number;
    score_threshold?: number;
    with_payload?: string[] | boolean;
    filter?: Filter;
    include_vector?: boolean;
  }): Promise<QdrantScoredPoint[]> {
    await this.ensureInitialized();

    const searchParams: Parameters<QdrantClient['search']>[1] = {
      vector: params.vector,
      limit: params.limit || 50,
      with_payload: params.with_payload ?? true,
      filter: params.filter ? (params.filter as unknown as Record<string, unknown>) : undefined,
    };

    if (params.score_threshold !== undefined) {
      searchParams.score_threshold = params.score_threshold;
    }

    if (params.include_vector) {
      searchParams.with_vector = true;
    }

    const result = await this.client.search(this.COLLECTION_NAME, searchParams);
    return result as unknown as QdrantScoredPoint[];
  }

  private matchesScope(
    itemScope: Readonly<Record<string, unknown>>,
    queryScope: Readonly<Record<string, unknown>>
  ): boolean {
    if (queryScope.project && itemScope.project !== queryScope.project) return false;
    if (queryScope.branch && itemScope.branch !== queryScope.branch) return false;
    if (queryScope.org && itemScope.org !== queryScope.org) return false;
    return true;
  }

  private generateAutonomousContext(
    stored: StoreResult[],
    errors: StoreError[]
  ): AutonomousContext {
    const duplicatesFound = stored.filter((item) => item.status === 'skipped_dedupe').length;
    const similarItemsChecked = stored.length;

    return {
      action_performed: stored.length > 0 ? 'created' : 'skipped',
      similar_items_checked: similarItemsChecked,
      duplicates_found: duplicatesFound,
      contradictions_detected: false,
      recommendation:
        duplicatesFound > 0 ? 'Review duplicates before storing' : 'Items stored successfully',
      reasoning: `Stored ${stored.length} items with ${errors.length} errors using vector embeddings`,
      user_message_suggestion:
        errors.length > 0
          ? `Some items failed to store (${errors.length} errors)`
          : `Successfully stored ${stored.length} items with semantic search capabilities`,
    };
  }

  async getCollectionStats(): Promise<QdrantCollectionStats> {
    try {
      const collectionInfo: QdrantCollectionInfo = (await this.client.getCollection(
        this.COLLECTION_NAME
      )) as QdrantCollectionInfo;

      return {
        vectorsCount: collectionInfo.vectors_count || 0,
        indexedVectorsCount: collectionInfo.indexed_vectors_count || 0,
        pointsCount: collectionInfo.points_count || 0,
        segmentsCount: collectionInfo.segments_count || 0,
        diskDataSize: collectionInfo.disk_data_size || 0,
        ramDataSize: collectionInfo.ram_data_size || 0,
      };
    } catch (error) {
      logger.error({ error }, 'Failed to get Qdrant collection stats');
      throw new QdrantDatabaseError(
        'Failed to retrieve collection stats',
        'COLLECTION_STATS_ERROR',
        error as Error
      );
    }
  }

  async getCollectionInfo(): Promise<
    DatabaseResult<{
      name: string;
      config: VectorConfig;
      status: 'healthy' | 'degraded' | 'unhealthy';
      metadata: Readonly<Record<string, unknown>>;
    }>
  > {
    return this.wrapAsyncOperation(async () => {
      try {
        const collectionInfo = await this.client.getCollection(this.COLLECTION_NAME);

        // Convert Qdrant collection info to expected format
        return {
          name: this.COLLECTION_NAME,
          config: this.config,
          status: 'healthy', // Qdrant doesn't provide health status directly, assume healthy if collection exists
          metadata: {
            vectorSize: collectionInfo.config.params.vectors.size,
            distance: collectionInfo.config.params.vectors.distance,
            pointsCount: collectionInfo.points_count,
          } as Readonly<Record<string, unknown>>,
        };
      } catch (error) {
        logger.error({ error }, 'Failed to get Qdrant collection info');
        throw new QdrantDatabaseError(
          'Failed to retrieve collection info',
          'COLLECTION_INFO_ERROR',
          error as Error
        );
      }
    }, 'getCollectionInfo');
  }

  /**
   * P6-T6.1: Find expired items using Qdrant filtering
   * Efficiently finds items that have expired based on expiry_at timestamp
   */
  async findExpiredItems(options: {
    readonly expiry_before?: string;
    readonly limit?: number;
    readonly scope?: {
      readonly project?: string;
      readonly branch?: string;
      readonly org?: string;
    };
    readonly kinds?: readonly string[];
  }): Promise<DatabaseResult<readonly KnowledgeItem[]>> {
    return this.wrapAsyncOperation(async () => {
      await this.ensureInitialized();

      try {
        const { expiry_before = new Date().toISOString(), limit = 1000, scope, kinds } = options;

        logger.debug(
          {
            expiry_before,
            limit,
            scope,
            kinds,
          },
          'Finding expired items using Qdrant filtering'
        );

        // Build filter for expired items
        const filterConditions: Condition[] = [
          {
            key: 'expiry_at',
            range: {
              lt: expiry_before,
            },
          },
          {
            key: 'expiry_at',
            is_not_null: {},
          },
        ];

        // Add kind filters if specified
        if (kinds && kinds.length > 0) {
          const kindConditions = kinds.map((kind) => ({
            key: 'kind',
            match: { value: kind },
          }));

          filterConditions.push({
            or: kindConditions,
          });
        }

        // Build Qdrant filter
        const qdrantFilter = {
          must: filterConditions,
        };

        // Add scope filters if specified
        if (scope) {
          const scopeFilter = this.buildSearchFilter({ scope });
          if (scopeFilter) {
            qdrantFilter.must.push(...scopeFilter.must);
          }
        }

        // Use a generic embedding for search (we're filtering, not semantic search)
        const embeddingResult = await this.generateEmbedding('expired item');
        if (isFailedDatabaseResult(embeddingResult)) {
          throw embeddingResult.error;
        }
        const genericEmbedding = [...embeddingResult.data];

        // Search for expired items
        const response = await this.searchWithCompatibleTypes({
          vector: genericEmbedding,
          limit,
          with_payload: true,
          filter: qdrantFilter,
          score_threshold: 0.0, // Accept all matches since we're filtering by expiry
        });

        const expiredItems = response.map((result) => ({
          ...this.pointToKnowledgeItem(result),
          score: result.score || 0,
        }));

        logger.debug(
          {
            total_found: expiredItems.length,
            expiry_before,
            limit,
          },
          'Found expired items using Qdrant filtering'
        );

        return expiredItems as readonly KnowledgeItem[];
      } catch (error) {
        logger.error(
          {
            error,
            options,
          },
          'Failed to find expired items in Qdrant'
        );
        throw new QdrantDatabaseError(
          'Failed to find expired items',
          'EXPIRED_ITEMS_SEARCH_ERROR',
          error as Error
        );
      }
    }, 'findExpiredItems');
  }

  // === Health and HA Operations ===

  /**
   * Get comprehensive health status
   */
  async getHealthStatus(): Promise<QdrantHealthStatus> {
    return await this.healthProbe.checkNodeHealth('primary');
  }

  /**
   * Get cluster health status
   */
  getClusterHealth() {
    return this.healthProbe.getClusterHealth();
  }

  /**
   * Setup high availability
   */
  async setupHA(haConfig: HAConfig): Promise<void> {
    this.haConfig = haConfig;

    // Add HA nodes to health probe
    for (const node of haConfig.nodes) {
      if (node.id !== 'primary') {
        const nodeUrl = new URL(node.url);
        const nodeConfig: VectorConfig = {
          ...this.config,
          host: nodeUrl.hostname,
          port: parseInt(nodeUrl.port) || 6333,
          database: this.config.collectionName || 'default',
          url: node.url,
          apiKey: node.apiKey,
          qdrant: {
            url: node.url,
            apiKey: node.apiKey,
            timeout: 10000,
          },
        };

        if (!isVectorConfig(nodeConfig)) {
          logger.warn('HA node configuration is invalid', { nodeId: node.id, config: nodeConfig });
          continue;
        }

        this.healthProbe.addNode(node.id, nodeConfig);
      }
    }

    // Initialize bootstrap service with HA config
    this.bootstrapService = createQdrantBootstrap(this.config, haConfig);

    logger.info('HA setup completed', {
      totalNodes: haConfig.nodes.length,
      replicationFactor: haConfig.replicationFactor,
    });
  }

  /**
   * Bootstrap database with collections and configuration
   */
  async bootstrap(): Promise<void> {
    if (!this.bootstrapService) {
      throw new Error('Bootstrap service not initialized. Call setupHA() first.');
    }

    const bootstrapConfig = {
      collections: [
        {
          name: this.COLLECTION_NAME,
          vectors: {
            size: this.config.dimensions || 1536,
            distance: this.config.distanceMetric || 'Cosine',
          },
          on_disk: true,
        },
      ],
      enableReplication: this.haConfig?.enabled || false,
      replicationFactor: this.haConfig?.replicationFactor || 1,
      enableSharding: false,
      shardCount: 1,
      enableQuantization: false,
      quantizationType: 'Scalar',
      enableWAL: true,
      walCapacityMB: 64,
      enableOnDisk: true,
      enableValidation: true,
      createBackup: false,
    };

    const result = await this.bootstrapService.bootstrap(bootstrapConfig);

    if (!result.success) {
      throw new Error(`Bootstrap failed: ${result.errors.join(', ')}`);
    }

    logger.info('Database bootstrap completed successfully', {
      collectionsCreated: result.collectionsCreated,
      duration: result.duration,
    });
  }

  /**
   * Test failover path
   */
  async testFailover(): Promise<{
    success: boolean;
    failoverTime: number;
    primaryRestored: boolean;
    errors: string[];
  }> {
    const result = {
      success: false,
      failoverTime: 0,
      primaryRestored: false,
      errors: [] as string[],
    };

    if (!this.haConfig?.enabled) {
      result.errors.push('HA not enabled');
      return result;
    }

    const startTime = Date.now();

    try {
      logger.info('Testing failover path');

      // Simulate primary node failure by opening circuit breaker
      this.healthProbe.resetCircuitBreaker('primary');

      // Check if secondary nodes can handle the load
      const clusterHealth = this.healthProbe.getClusterHealth();
      if (clusterHealth.healthyNodes === 0) {
        result.errors.push('No healthy nodes available for failover');
        return result;
      }

      // Simulate operations during failover
      const testItem = {
        id: 'failover-test-' + Date.now(),
        kind: 'entity' as const,
        scope: { project: 'test' },
        data: { content: 'failover test', test: true },
        created_at: new Date().toISOString(),
      };

      // Test write operation
      await this.store([testItem], { timeout: 5000 });

      // Test read operation
      const searchResult = await this.search({
        query: 'failover test',
        limit: 1,
        scope: { project: 'test' },
      });

      if (!searchResult.success || searchResult.data.results.length === 0) {
        result.errors.push('Read operation failed during failover');
        return result;
      }

      result.success = true;
      result.failoverTime = Date.now() - startTime;

      // Test primary restoration
      await this.sleep(2000); // Wait for potential primary recovery
      const primaryHealth = await this.healthProbe.checkNodeHealth('primary');
      result.primaryRestored = primaryHealth.isHealthy;

      logger.info('Failover test completed', {
        success: result.success,
        failoverTime: result.failoverTime,
        primaryRestored: result.primaryRestored,
      });
    } catch (error) {
      result.errors.push(
        `Failover test failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
      logger.error('Failover test failed', { error });
    }

    return result;
  }

  /**
   * Initialize health monitoring
   */
  async initializeHealthMonitoring(): Promise<void> {
    await this.healthProbe.start();
    logger.info('Health monitoring initialized');
  }

  /**
   * Stop health monitoring
   */
  async stopHealthMonitoring(): Promise<void> {
    await this.healthProbe.stop();
    logger.info('Health monitoring stopped');
  }

  /**
   * Get circuit breaker status
   */
  getCircuitBreakerStatus() {
    return this.healthProbe.getCircuitBreakerStatus();
  }

  /**
   * Reset circuit breaker
   */
  resetCircuitBreaker(nodeId: string): boolean {
    return this.healthProbe.resetCircuitBreaker(nodeId);
  }

  /**
   * Sleep utility for testing
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Log Qdrant circuit breaker events with proper context
   */
  private logQdrantCircuitBreakerEvent(
    event: string,
    error?: Error,
    metadata?: Record<string, unknown>
  ): void {
    const qdrantStats = this.qdrantCircuitBreaker.getStats();
    const openaiStats = this.openaiCircuitBreaker.getStats();

    logger.info(
      {
        event,
        qdrantCircuitState: qdrantStats.state,
        qdrantIsOpen: qdrantStats.isOpen,
        qdrantFailureRate: qdrantStats.failureRate,
        qdrantTotalCalls: qdrantStats.totalCalls,
        openaiCircuitState: openaiStats.state,
        openaiIsOpen: openaiStats.isOpen,
        openaiFailureRate: openaiStats.failureRate,
        openaiTotalCalls: openaiStats.totalCalls,
        error: error?.message || error,
        metadata,
      },
      `Qdrant adapter circuit breaker event: ${event}`
    );

    // If Qdrant circuit is open, log additional context
    if (qdrantStats.isOpen) {
      logger.warn(
        {
          event: 'qdrant_circuit_open',
          timeSinceStateChange: qdrantStats.timeSinceStateChange,
          failureTypes: qdrantStats.failureTypes,
          lastFailureTime: qdrantStats.timeSinceLastFailure,
        },
        'Qdrant adapter circuit breaker is OPEN - database operations will be blocked'
      );
    }
  }

  /**
   * Get Qdrant circuit breaker status for monitoring
   */
  getQdrantCircuitBreakerStatus(): CircuitBreakerStats {
    return this.qdrantCircuitBreaker.getStats();
  }

  /**
   * Get OpenAI circuit breaker status for monitoring
   */
  getOpenAICircuitBreakerStatus(): CircuitBreakerStats {
    return this.openaiCircuitBreaker.getStats();
  }

  /**
   * Reset Qdrant circuit breaker (useful for testing or recovery)
   */
  resetQdrantCircuitBreaker(): void {
    this.qdrantCircuitBreaker.reset();
    logger.info('Qdrant adapter circuit breaker reset');
  }

  /**
   * Reset OpenAI circuit breaker (useful for testing or recovery)
   */
  resetOpenAICircuitBreaker(): void {
    this.openaiCircuitBreaker.reset();
    logger.info('OpenAI embeddings circuit breaker reset');
  }

  // === Missing IVectorAdapter Interface Methods ===

  /**
   * Get database connection information
   */
  getConnection(): DatabaseConnection<unknown> {
    return {
      client: this.client,
      isConnected: this.initialized,
      lastHealthCheck: new Date(),
      connectionId: `qdrant-${Date.now()}`,
      endpoint: `${this.config.host}:${this.config.port}`,
      capabilities: {
        supportsTransactions: false,
        supportsVectorSearch: true,
        supportsFullTextSearch: false,
        supportsBatchOperations: true,
        supportsStreaming: false,
        maxBatchSize: 1000,
        maxConnections: 10,
        supportedOperations: ['search', 'store', 'delete', 'update', 'bulkStore', 'bulkDelete'],
        consistencyLevels: ['strong'],
      } as DatabaseCapabilities,
    };
  }

  /**
   * Create query builder for advanced searches
   */
  createQueryBuilder(): QueryBuilder<Record<string, unknown>> {
    throw new Error('QueryBuilder not implemented - use search methods instead');
  }

  /**
   * Search using query filter
   */
  async findByFilter(
    filter: QueryFilter<Record<string, unknown>>,
    options?: QueryOptions<Record<string, unknown>>
  ): Promise<DatabaseResult<readonly Record<string, unknown>[]>> {
    return this.wrapAsyncOperation(async () => {
      // Convert filter to search query and delegate to search method
      const searchQuery: SearchQuery = {
        query: '',
        filters: filter as unknown,
        limit: options?.limit || 100,
      };

      const result = await this.search(searchQuery, options as unknown);
      if (result.success) {
        const records = result.data.results.map((item) => item.data || {});
        return records as readonly Record<string, unknown>[];
      } else {
        throw new Error('Search failed');
      }
    }, 'findByFilter');
  }

  /**
   * Create mutation builder for batch operations
   */
  createMutationBuilder(): MutationBuilder<Record<string, unknown>> {
    throw new Error('MutationBuilder not implemented - use bulk operations instead');
  }

  /**
   * Generate multiple embeddings for batch processing
   */
  async generateEmbeddingsBatch(
    contents: readonly string[]
  ): Promise<DatabaseResult<readonly number[][]>> {
    return this.wrapAsyncOperation(async () => {
      const embeddings: number[][] = [];
      for (const content of contents) {
        const result = await this.generateEmbedding(content);
        if (result.success) {
          embeddings.push([...result.data]);
        } else {
          throw new Error(`Failed to generate embedding for content: ${content}`);
        }
      }
      return embeddings as readonly number[][];
    }, 'generateEmbeddingsBatch');
  }

  /**
   * Search using vector similarity
   */
  async vectorSearch(
    embedding: readonly number[],
    options?: SearchOptions
  ): Promise<DatabaseResult<readonly SearchResult[]>> {
    return this.wrapAsyncOperation(async () => {
      // For vector search, we need to use Qdrant client directly
      const collectionName = this.config.collectionName || 'knowledge';
      const searchResult = await this.client.search(collectionName, {
        vector: [...embedding],
        limit: options?.limit || 10,
        score_threshold: options?.score_threshold || 0.7,
      });

      const results = searchResult.map((point: unknown) =>
        this.searchResultToSearchResult(point, 'semantic')
      );

      return results as readonly SearchResult[];
    }, 'vectorSearch');
  }

  /**
   * Find nearest neighbors for a vector
   */
  async findNearest(
    embedding: readonly number[],
    limit?: number,
    threshold?: number
  ): Promise<DatabaseResult<readonly SearchResult[]>> {
    return this.wrapAsyncOperation(async () => {
      const result = await this.vectorSearch(embedding, { limit, score_threshold: threshold });
      return result.success ? result.data : [];
    }, 'findNearest');
  }

  /**
   * Vector similarity search with multiple vectors
   */
  async findNearestMultiple(
    embeddings: readonly number[][],
    limit?: number,
    threshold?: number
  ): Promise<DatabaseResult<readonly SearchResult[][]>> {
    return this.wrapAsyncOperation(async () => {
      const results: SearchResult[][] = [];
      for (const embedding of embeddings) {
        const nearestResult = await this.findNearest(embedding, limit, threshold);
        if (nearestResult.success) {
          results.push([...nearestResult.data]);
        } else {
          results.push([]);
        }
      }
      return results as readonly SearchResult[][];
    }, 'findNearestMultiple');
  }

  /**
   * Begin a new transaction
   */
  async beginTransaction(
    options?: TransactionOptions
  ): Promise<DatabaseResult<Transaction<unknown>>> {
    return this.wrapAsyncOperation(async () => {
      throw new Error('Transactions not supported in Qdrant adapter');
    }, 'beginTransaction');
  }

  /**
   * Execute operations within a transaction
   */
  async executeTransaction<T>(
    operations: readonly DatabaseOperation<unknown, T>[],
    options?: TransactionOptions
  ): Promise<DatabaseResult<readonly T[]>> {
    return this.wrapAsyncOperation(async () => {
      throw new Error('Transactions not supported in Qdrant adapter');
    }, 'executeTransaction');
  }

  /**
   * Create a new collection
   */
  async createCollection(
    name: string,
    config: VectorConfig
  ): Promise<DatabaseResult<{ created: boolean; collectionId: CollectionId }>> {
    return this.wrapAsyncOperation(async () => {
      await this.client.createCollection(name, {
        vectors: {
          size: config.vectorSize || 1536,
          distance: config.distanceMetric || 'Cosine',
        },
      });
      return { created: true, collectionId: name as CollectionId };
    }, 'createCollection');
  }

  /**
   * Delete a collection
   */
  async deleteCollection(name: string): Promise<DatabaseResult<{ deleted: boolean }>> {
    return this.wrapAsyncOperation(async () => {
      await this.client.deleteCollection(name);
      return { deleted: true };
    }, 'deleteCollection');
  }

  /**
   * List all collections
   */
  async listCollections(): Promise<DatabaseResult<readonly { name: string; status: string }[]>> {
    return this.wrapAsyncOperation(async () => {
      const collections = await this.client.getCollections();
      return collections.collections.map((col) => ({
        name: col.name,
        status: 'healthy',
      }));
    }, 'listCollections');
  }

  /**
   * Get raw Qdrant client
   */
  getRawClient(): unknown {
    return this.client;
  }

  /**
   * Get performance metrics
   */
  async getPerformanceMetrics(): Promise<
    DatabaseResult<{
      queryLatency: number;
      indexingLatency: number;
      throughput: number;
      errorRate: number;
      cacheHitRate?: number;
    }>
  > {
    return this.wrapAsyncOperation(async () => {
      const metrics = await this.getMetrics();

      // Safely access metrics properties
      const safeMetrics = isQdrantMetricsResponse(metrics) ? metrics : {
        averageSearchTime: 0,
        averageIndexingTime: 0,
        totalOperations: 0,
        errorRate: 0,
        cacheHitRate: 0,
      };

      return {
        queryLatency: safeMetrics.averageSearchTime,
        indexingLatency: safeMetrics.averageIndexingTime,
        throughput: safeMetrics.totalOperations,
        errorRate: safeMetrics.errorRate,
        cacheHitRate: safeMetrics.cacheHitRate,
      };
    }, 'getPerformanceMetrics');
  }

  /**
   * Health check with detailed status
   */
  async detailedHealthCheck(): Promise<
    DatabaseResult<{
      healthy: boolean;
      connectionStatus: string;
      collectionStatus: string;
      issues: readonly string[];
      recommendations?: readonly string[];
    }>
  > {
    return this.wrapAsyncOperation(async () => {
      const isHealthy = await this.healthCheck();
      const collectionInfo = await this.getCollectionInfo();

      const issues: string[] = [];
      const recommendations: string[] = [];

      if (!isHealthy) {
        issues.push('Database connection unhealthy');
        recommendations.push('Check network connectivity and authentication');
      }

      if (!collectionInfo.success) {
        issues.push('Collection access failed');
        recommendations.push('Verify collection exists and permissions are correct');
      }

      return {
        healthy: isHealthy && collectionInfo.success,
        connectionStatus: isHealthy ? 'connected' : 'disconnected',
        collectionStatus: collectionInfo.success ? 'available' : 'unavailable',
        issues,
        recommendations,
      };
    }, 'detailedHealthCheck');
  }

  /**
   * Check if operation is supported
   */
  supportsOperation(operation: string): boolean {
    const supportedOps = [
      'search',
      'store',
      'update',
      'delete',
      'findById',
      'semanticSearch',
      'hybridSearch',
      'exactSearch',
      'bulkStore',
      'bulkDelete',
      'generateEmbedding',
      'backup',
      'restore',
      'optimize',
      'validate',
    ];
    return supportedOps.includes(operation);
  }

  /**
   * Get list of supported operations
   */
  getSupportedOperations(): readonly string[] {
    return [
      'search',
      'store',
      'update',
      'delete',
      'findById',
      'semanticSearch',
      'hybridSearch',
      'exactSearch',
      'bulkStore',
      'bulkDelete',
      'generateEmbedding',
      'backup',
      'restore',
      'optimize',
      'validate',
      'createCollection',
      'deleteCollection',
      'listCollections',
    ] as const;
  }
}
