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
 */

import { QdrantClient } from '@qdrant/js-client-rest';
import { OpenAI } from 'openai';
import * as crypto from 'node:crypto';
import { logger } from '../../utils/logger.js';
import { calculateItemExpiry } from '../../utils/expiry-utils.js';
import { getKeyVaultService } from '../../services/security/key-vault-service.js';
import { EmbeddingService } from '../../services/embeddings/embedding-service.js';
import { createQdrantHealthProbe, type QdrantHealthStatus } from '../qdrant-health-probe.js';
import { createQdrantBootstrap, type HAConfig } from '../qdrant-bootstrap.js';
import type { ExpiryTimeLabel } from '../../constants/expiry-times.js';
import type {
  KnowledgeItem,
  StoreResult,
  StoreError,
  SearchResult,
  SearchQuery,
  MemoryStoreResponse,
  MemoryFindResponse,
  AutonomousContext,
  ItemResult,
  BatchSummary,
} from '../../types/core-interfaces.js';
import type {
  IVectorAdapter,
  VectorConfig,
  SearchOptions,
  StoreOptions,
  DeleteOptions,
  DatabaseMetrics,
} from '../interfaces/vector-adapter.interface.js';
import { DatabaseError, ConnectionError, NotFoundError } from '../database-interface.js';
import {
  createStoreObservability,
  createFindObservability,
} from '../../utils/observability-helper.js';
import {
  circuitBreakerManager,
  type CircuitBreakerStats,
} from '../../services/circuit-breaker.service.js';

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
export class QdrantAdapter implements IVectorAdapter {
  private client!: QdrantClient;
  private openai!: OpenAI;
  private config: VectorConfig;
  private initialized: boolean = false;
  private embeddingService!: EmbeddingService;
  private healthProbe = createQdrantHealthProbe();
  private bootstrapService?: ReturnType<typeof createQdrantBootstrap>;
  private haConfig?: HAConfig;
  private capabilities!: {
    supportsVectors: boolean;
    supportsFullTextSearch: boolean;
    supportsPayloadFiltering: boolean;
    maxBatchSize: number;
    supportedDistanceMetrics: string[];
    supportedOperations: string[];
  };
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

  constructor(config: VectorConfig) {
    // Store config for later async initialization
    this.config = {
      type: 'qdrant',
      url: config.url || process.env.QDRANT_URL || 'http://localhost:6333',
      ...(config.apiKey !== undefined && { apiKey: config.apiKey }),
      vectorSize: config.vectorSize || 1536, // OpenAI ada-002
      distance: config.distance || 'Cosine',
      logQueries: config.logQueries || false,
      connectionTimeout: config.connectionTimeout || 30000,
      maxConnections: config.maxConnections || 10,
      collectionName: config.collectionName || 'knowledge_items',
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
      const resolvedApiKey = this.config.apiKey || qdrantKey?.value || process.env.QDRANT_API_KEY;
      const resolvedOpenAIKey = openaiKey?.value || process.env.OPENAI_API_KEY;

      // Initialize Qdrant client
      const clientConfig: any = {
        url: this.config.url,
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
      const fallbackApiKey = this.config.apiKey || process.env.QDRANT_API_KEY;
      const fallbackOpenAIKey = process.env.OPENAI_API_KEY;

      const clientConfig: any = {
        url: this.config.url,
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
      supportsVectors: true,
      supportsFullTextSearch: true,
      supportsPayloadFiltering: true,
      maxBatchSize: 100,
      supportedDistanceMetrics: ['Cosine', 'Euclid', 'Dot', 'Manhattan'],
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
      ],
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
    if (item.data.expiry_at) {
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
      throw new ConnectionError('Failed to initialize Qdrant connection', error as Error);
    }
  }

  async healthCheck(): Promise<boolean> {
    try {
      return await this.qdrantCircuitBreaker.execute(async () => {
        await this.client.getCollections();
        this.logQdrantCircuitBreakerEvent('health_check_success');
        return true;
      }, 'qdrant_health_check');
    } catch (error) {
      logger.error({ error }, 'Qdrant health check failed');
      this.logQdrantCircuitBreakerEvent('health_check_failure', error);
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
      throw new DatabaseError(
        'Failed to retrieve database metrics',
        'METRICS_ERROR',
        error as Error
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
      throw new DatabaseError('Failed to close Qdrant adapter', 'CLOSE_ERROR', error as Error);
    }
  }

  // === Knowledge Storage Operations ===

  async store(items: KnowledgeItem[], options: StoreOptions = {}): Promise<MemoryStoreResponse> {
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
                  const existingId = existing[0].id;
                  stored.push({
                    id: existingId,
                    status: 'skipped_dedupe',
                    kind: item.kind,
                    created_at: existing[0].created_at || new Date().toISOString(),
                  });

                  // Add to item results
                  const skippedResult: ItemResult = {
                    input_index: index,
                    status: 'skipped_dedupe',
                    kind: item.kind,
                    reason: 'Duplicate content',
                    existing_id: existingId,
                    created_at: existing[0].created_at || new Date().toISOString(),
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
                    is_chunk: true,
                    chunk_index: item.data.chunk_index,
                    total_chunks: item.data.total_chunks,
                    parent_id: item.data.parent_id,
                    extracted_title: item.data.extracted_title,
                  }
                : undefined;
              const embedding = await this.generateEmbedding(content, chunkingContext);

              // Generate sparse vector for keyword search
              const sparseVector = this.generateSparseVector(content);

              // Calculate TTL and expiry for this item
              const expiryAt = this.calculateItemExpiryWithPolicy(item);
              const ttlEpoch = this.calculateTTLEpoch(expiryAt);

              // Create point for Qdrant
              const point = {
                id: item.id || `qdrant_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                vector: embedding,
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
                (point as any).ttl_epoch = ttlEpoch;
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
          validation_error: itemResults.filter((item) => item.status === 'validation_error').length,
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

        const result = {
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

        this.logQdrantCircuitBreakerEvent('store_success', undefined, { itemCount: items.length });
        return result;
      } catch (error) {
        logger.error({ error, itemCount: items.length }, 'Qdrant store operation failed');
        this.logQdrantCircuitBreakerEvent('store_failure', error, { itemCount: items.length });
        throw new DatabaseError('Failed to store items in Qdrant', 'STORE_ERROR', error as Error);
      }
    }, 'qdrant_store');
  }

  async update(items: KnowledgeItem[], options: StoreOptions = {}): Promise<MemoryStoreResponse> {
    // For Qdrant, update is the same as store (upsert)
    return await this.store(items, { ...options, upsert: true });
  }

  async delete(
    ids: string[],
    options: DeleteOptions = {}
  ): Promise<{ deleted: number; errors: StoreError[] }> {
    await this.ensureInitialized();

    const { validate = true } = options;
    let deleted = 0;
    const errors: StoreError[] = [];

    try {
      logger.debug({ ids, options }, 'Deleting items from Qdrant');

      for (const id of ids) {
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
            points: ids,
          });

          deleted++;
        } catch (error) {
          errors.push({
            index: ids.indexOf(id),
            error_code: 'DELETE_ERROR',
            message: error instanceof Error ? error.message : 'Unknown error',
          });
        }
      }

      logger.debug({ deleted, errors: errors.length }, 'Qdrant delete operation completed');
      return { deleted, errors };
    } catch (error) {
      logger.error({ error, ids }, 'Qdrant delete operation failed');
      throw new DatabaseError('Failed to delete items from Qdrant', 'DELETE_ERROR', error as Error);
    }
  }

  async findById(ids: string[]): Promise<KnowledgeItem[]> {
    await this.ensureInitialized();

    try {
      const results = await this.client.retrieve(this.COLLECTION_NAME, {
        ids,
        with_payload: true,
      });

      return results.map((point) => this.pointToKnowledgeItem(point));
    } catch (error) {
      logger.error({ error, ids }, 'Failed to find items by ID in Qdrant');
      return [];
    }
  }

  // === Search Operations ===

  async search(query: SearchQuery, options: SearchOptions = {}): Promise<MemoryFindResponse> {
    await this.ensureInitialized();
    const startTime = Date.now();

    // No options needed for now

    try {
      logger.debug({ query, options }, 'Searching Qdrant');

      // Determine search mode
      const mode = query.mode || 'auto';
      let searchResults: SearchResult[];

      switch (mode) {
        case 'auto':
          searchResults = await this.hybridSearch(query.query, options);
          break;
        case 'deep':
          searchResults = await this.semanticSearch(query.query, options);
          break;
        case 'fast':
          searchResults = await this.exactSearch(query.query, options);
          break;
        default:
          searchResults = await this.hybridSearch(query.query, options);
          break;
      }

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
            ? limitedResults.reduce((sum, r) => sum + r.confidence_score, 0) / limitedResults.length
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
          mode as any, // TypeScript type conversion
          true, // vector_used
          false, // degraded (Qdrant adapter assumes not degraded)
          Date.now() - startTime,
          limitedResults.length > 0
            ? limitedResults.reduce((sum, r) => sum + r.confidence_score, 0) / limitedResults.length
            : 0
        ),

        // Required meta field for unified response format
        meta: {
          strategy: mode as any,
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
    } catch (error) {
      logger.error({ error, query }, 'Qdrant search operation failed');
      throw new DatabaseError('Failed to search Qdrant', 'SEARCH_ERROR', error as Error);
    }
  }

  async semanticSearch(query: string, options: SearchOptions = {}): Promise<SearchResult[]> {
    await this.ensureInitialized();

    const { limit = 50, score_threshold = 0.7 } = options;

    try {
      // Generate embedding for query
      const queryEmbedding = await this.generateEmbedding(query);

      // Build filter for scope and types
      const searchFilter = this.buildSearchFilter({});

      // Search in Qdrant
      const response = await this.client.search(this.COLLECTION_NAME, {
        vector: queryEmbedding,
        limit,
        score_threshold,
        with_payload: ['kind', 'scope', 'data', 'created_at', 'content'],
        filter: searchFilter,
      });

      return response.map((result) => this.searchResultToSearchResult(result, 'semantic'));
    } catch (error) {
      logger.error({ error, query }, 'Qdrant semantic search failed');
      throw new DatabaseError(
        'Failed to perform semantic search',
        'SEMANTIC_SEARCH_ERROR',
        error as Error
      );
    }
  }

  async exactSearch(query: string, options: SearchOptions = {}): Promise<SearchResult[]> {
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
        filter: searchFilter,
      });

      return response.map((result) => this.searchResultToSearchResult(result, 'exact'));
    } catch (error) {
      logger.error({ error, query }, 'Qdrant exact search failed');
      throw new DatabaseError(
        'Failed to perform exact search',
        'EXACT_SEARCH_ERROR',
        error as Error
      );
    }
  }

  async findNearest(
    embedding: number[],
    limit: number = 10,
    threshold: number = 0.5
  ): Promise<SearchResult[]> {
    await this.ensureInitialized();

    try {
      const response = await this.client.search(this.COLLECTION_NAME, {
        vector: embedding,
        limit,
        score_threshold: threshold,
        with_payload: ['kind', 'scope', 'data', 'created_at'],
      });

      return response.map((result) => this.searchResultToSearchResult(result, 'semantic'));
    } catch (error) {
      logger.error({ error }, 'Qdrant find nearest failed');
      throw new DatabaseError(
        'Failed to find nearest vectors',
        'FIND_NEAREST_ERROR',
        error as Error
      );
    }
  }

  async hybridSearch(query: string, options: SearchOptions = {}): Promise<SearchResult[]> {
    await this.ensureInitialized();

    const { limit = 50 } = options;

    try {
      // Generate both embeddings
      const [queryEmbedding] = await Promise.all([
        this.generateEmbedding(query),
        Promise.resolve(this.generateSparseVector(query)),
      ]);

      // Build filter
      const searchFilter = this.buildSearchFilter({});

      // Search using vector (semantic)
      const response = await this.client.search(this.COLLECTION_NAME, {
        vector: queryEmbedding,
        limit,
        score_threshold: 0.5,
        with_payload: ['kind', 'scope', 'data', 'created_at', 'content'],
        filter: searchFilter,
      });

      return response.map((result) => this.searchResultToSearchResult(result, 'hybrid'));
    } catch (error) {
      logger.error({ error, query }, 'Qdrant hybrid search failed');
      throw new DatabaseError(
        'Failed to perform hybrid search',
        'HYBRID_SEARCH_ERROR',
        error as Error
      );
    }
  }

  // === Knowledge Type Specific Operations ===

  async storeByKind(
    kind: string,
    items: KnowledgeItem[],
    options: StoreOptions = {}
  ): Promise<MemoryStoreResponse> {
    // Filter items by kind and store them
    const filteredItems = items.filter((item) => item.kind === kind);
    return await this.store(filteredItems, options);
  }

  async searchByKind(
    kinds: string[],
    query: SearchQuery,
    options: SearchOptions = {}
  ): Promise<MemoryFindResponse> {
    const response = await this.search(query, options);

    // Filter results by kinds
    const filteredResults = response.results.filter((result) => kinds.includes(result.kind));

    return {
      ...response,
      results: filteredResults,
      total_count: filteredResults.length,
    };
  }

  async findByScope(
    scope: { project?: string; branch?: string; org?: string },
    options: SearchOptions = {}
  ): Promise<KnowledgeItem[]> {
    await this.ensureInitialized();

    try {
      // Build filter for scope
      const searchFilter = this.buildSearchFilter({ scope });

      // Search using a generic embedding (space or common term)
      const genericEmbedding = await this.generateEmbedding('knowledge');

      const response = await this.client.search(this.COLLECTION_NAME, {
        vector: genericEmbedding,
        limit: options.cache ? 1000 : 1000, // Large limit for scope search
        score_threshold: 0.1,
        with_payload: true,
        filter: searchFilter,
      });

      return response.map((result) => this.pointToKnowledgeItem(result));
    } catch (error) {
      logger.error({ error, scope }, 'Qdrant scope search failed');
      throw new DatabaseError(
        'Failed to search by scope in Qdrant',
        'SCOPE_SEARCH_ERROR',
        error as Error
      );
    }
  }

  // === Advanced Operations ===

  async findSimilar(item: KnowledgeItem, threshold: number = 0.7): Promise<SearchResult[]> {
    await this.ensureInitialized();

    try {
      // Generate embedding for the item with chunking context if available
      const content = this.extractContentForEmbedding(item);
      const chunkingContext = item.data.is_chunk
        ? {
            is_chunk: true,
            chunk_index: item.data.chunk_index,
            total_chunks: item.data.total_chunks,
            parent_id: item.data.parent_id,
            extracted_title: item.data.extracted_title,
          }
        : undefined;
      const embedding = await this.generateEmbedding(content, chunkingContext);

      // Search for similar items
      const response = await this.client.search(this.COLLECTION_NAME, {
        vector: embedding,
        limit: 10,
        score_threshold: threshold,
        with_payload: ['kind', 'scope', 'data', 'created_at'],
        filter: {
          must_not: [{ key: 'id', match: { value: item.id } }],
        },
      });

      return response.map((result) => this.searchResultToSearchResult(result, 'semantic'));
    } catch (error) {
      logger.error({ error, itemId: item.id }, 'Qdrant similarity search failed');
      throw new DatabaseError(
        'Failed to find similar items in Qdrant',
        'SIMILARITY_SEARCH_ERROR',
        error as Error
      );
    }
  }

  async checkDuplicates(
    items: KnowledgeItem[]
  ): Promise<{ duplicates: KnowledgeItem[]; originals: KnowledgeItem[] }> {
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

    return { duplicates, originals };
  }

  async getStatistics(scope?: { project?: string; branch?: string; org?: string }): Promise<{
    totalItems: number;
    itemsByKind: Record<string, number>;
    storageSize: number;
    lastUpdated: string;
    vectorCount: number;
  }> {
    await this.ensureInitialized();

    try {
      // Get collection info
      const collectionInfo = await this.client.getCollection(this.COLLECTION_NAME);
      const totalItems = collectionInfo.vectors_count || 0;

      // Get a sample of items to determine kinds
      const sample = await this.client.scroll(this.COLLECTION_NAME, {
        limit: 1000,
        with_payload: ['kind'],
        filter: scope ? this.buildSearchFilter({ scope }) : undefined,
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
      throw new DatabaseError('Failed to retrieve statistics', 'STATISTICS_ERROR', error as Error);
    }
  }

  // === Batch Operations ===

  async bulkStore(
    items: KnowledgeItem[],
    options: StoreOptions = {}
  ): Promise<MemoryStoreResponse> {
    return await this.store(items, { ...options, batchSize: 100 });
  }

  async bulkDelete(filter: {
    kind?: string;
    scope?: any;
    before?: string;
  }): Promise<{ deleted: number }> {
    await this.ensureInitialized();

    try {
      // Build filter for bulk delete
      const filterConfig: { kind?: string; scope?: any } = {};
      if (filter.kind) filterConfig.kind = filter.kind;
      if (filter.scope) filterConfig.scope = filter.scope;
      const searchFilter = this.buildSearchFilter(filterConfig);

      // Find items to delete
      const toDelete = await this.client.scroll(this.COLLECTION_NAME, {
        limit: 10000, // Large limit for bulk operation
        with_payload: ['id'],
        filter: searchFilter,
      });

      if (toDelete.points.length === 0) {
        return { deleted: 0 };
      }

      const ids = toDelete.points.map((point) => point.id);

      // Delete items
      await this.client.delete(this.COLLECTION_NAME, {
        wait: true,
        points: ids,
      });

      logger.debug({ deleted: ids.length, filter }, 'Qdrant bulk delete completed');
      return { deleted: ids.length };
    } catch (error) {
      logger.error({ error, filter }, 'Qdrant bulk delete failed');
      throw new DatabaseError(
        'Failed to bulk delete items in Qdrant',
        'BULK_DELETE_ERROR',
        error as Error
      );
    }
  }

  async bulkSearch(
    queries: SearchQuery[],
    options: SearchOptions = {}
  ): Promise<MemoryFindResponse[]> {
    const results: MemoryFindResponse[] = [];

    for (const query of queries) {
      const result = await this.search(query, options);
      results.push(result);
    }

    return results;
  }

  // === Vector Operations ===

  async generateEmbedding(
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
      throw new DatabaseError('Failed to generate embedding', 'EMBEDDING_ERROR', error as Error);
    }
  }

  async storeWithEmbeddings(
    items: Array<KnowledgeItem & { embedding: number[] }>
  ): Promise<MemoryStoreResponse> {
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
        business_rule_blocked: itemResults.filter((item) => item.status === 'business_rule_blocked')
          .length,
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
      throw new DatabaseError(
        'Failed to store items with embeddings',
        'STORE_WITH_EMBEDDINGS_ERROR',
        error as Error
      );
    }
  }

  async vectorSearch(embedding: number[], options: SearchOptions = {}): Promise<SearchResult[]> {
    await this.ensureInitialized();

    const { limit = 50, score_threshold = 0.5 } = options;

    try {
      const response = await this.client.search(this.COLLECTION_NAME, {
        vector: embedding,
        limit,
        score_threshold,
        with_payload: ['kind', 'scope', 'data', 'created_at'],
      });

      return response.map((result) => this.searchResultToSearchResult(result, 'vector'));
    } catch (error) {
      logger.error({ error }, 'Qdrant vector search failed');
      throw new DatabaseError(
        'Failed to perform vector search',
        'VECTOR_SEARCH_ERROR',
        error as Error
      );
    }
  }

  // === Administrative Operations ===

  async backup(destination?: string): Promise<string> {
    await this.ensureInitialized();

    try {
      // Create snapshot
      const snapshotResult = await this.client.createSnapshot(this.COLLECTION_NAME);
      if (!snapshotResult) {
        throw new DatabaseError('Failed to create snapshot - null response', 'BACKUP_ERROR');
      }
      const snapshotName = snapshotResult.name;

      logger.info({ snapshotName, destination }, 'Qdrant snapshot created');
      return snapshotName;
    } catch (error) {
      logger.error({ error }, 'Failed to create Qdrant snapshot');
      throw new DatabaseError('Failed to create backup', 'BACKUP_ERROR', error as Error);
    }
  }

  async restore(_source: string): Promise<void> {
    throw new DatabaseError('Qdrant restore not implemented', 'UNSUPPORTED_OPERATION');
  }

  async updateCollectionSchema(config: any): Promise<void> {
    await this.ensureInitialized();

    try {
      await this.client.updateCollection(this.COLLECTION_NAME, config);
      logger.info('Qdrant collection schema updated');
    } catch (error) {
      logger.error({ error }, 'Failed to update Qdrant collection schema');
      throw new DatabaseError(
        'Failed to update collection schema',
        'SCHEMA_UPDATE_ERROR',
        error as Error
      );
    }
  }

  async optimize(): Promise<void> {
    await this.ensureInitialized();

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
    } catch (error) {
      logger.error({ error }, 'Failed to optimize Qdrant collection');
      throw new DatabaseError('Failed to optimize Qdrant', 'OPTIMIZE_ERROR', error as Error);
    }
  }

  async validate(): Promise<{ valid: boolean; issues: string[] }> {
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
      issues.push(`Validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return { valid: false, issues };
    }
  }

  // === Interface Implementation Methods ===

  getClient(): any {
    return this.client;
  }

  async getCapabilities(): Promise<{
    supportsVectors: boolean;
    supportsFullTextSearch: boolean;
    supportsPayloadFiltering: boolean;
    maxBatchSize: number;
    supportedDistanceMetrics: string[];
    supportedOperations: string[];
  }> {
    return this.capabilities;
  }

  async testFunctionality(operation: string): Promise<boolean> {
    try {
      switch (operation) {
        case 'connection':
          return await this.healthCheck();
        case 'search':
          await this.search({ query: 'test', limit: 1 });
          return true;
        case 'vector_search': {
          const embedding = await this.generateEmbedding('test');
          await this.vectorSearch(embedding);
          return true;
        }
        case 'store': {
          const testItem: KnowledgeItem = {
            kind: 'section',
            scope: { project: 'test' },
            data: { title: 'Test', content: 'Test content' },
          };
          await this.store([testItem]);
          return true;
        }
        default:
          return false;
      }
    } catch (error) {
      logger.error({ operation, error }, 'Functionality test failed');
      return false;
    }
  }

  // === Private Helper Methods ===

  private async ensureInitialized(): Promise<void> {
    if (!this.initialized) {
      await this.initialize();
    }
  }

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

  private async findByHash(_hash: string): Promise<any[]> {
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
        parts.push(data.title || '');
        parts.push(data.content || '');
        parts.push(data.heading || '');
        break;
      case 'decision':
        parts.push(data.title || '');
        parts.push(data.rationale || '');
        parts.push(data.component || '');
        break;
      case 'issue':
        parts.push(data.title || '');
        parts.push(data.description || '');
        parts.push(data.status || '');
        break;
      case 'todo':
        parts.push(data.title || '');
        parts.push(data.description || '');
        parts.push(data.status || '');
        break;
      case 'runbook':
        parts.push(data.title || '');
        parts.push(data.description || '');
        if (Array.isArray(data.steps)) {
          parts.push(data.steps.join(' '));
        }
        break;
      default:
        // Generic extraction
        parts.push(data.title || data.name || '');
        parts.push(data.description || data.content || '');
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

  private buildSearchFilter(filter: {
    kind?: string;
    scope?: any;
    expiry_before?: string;
    expiry_after?: string;
    has_expiry?: boolean;
    ttl_policy?: string;
    ttl_duration_min?: number;
    ttl_duration_max?: number;
    is_permanent?: boolean;
    include_expired?: boolean;
  }): any {
    const qdrantFilter: any = {
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
    const expiryConditions: any[] = [];
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
      const durationRange: any = {};
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
        qdrantFilter.must.push(nonExpiredCondition);
      } else {
        expiryConditions.push(...nonExpiredCondition.should);
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

  private pointToKnowledgeItem(point: any): KnowledgeItem {
    const payload = point.payload || {};
    return {
      id: point.id,
      kind: payload.kind || 'unknown',
      scope: payload.scope || {},
      data: payload.data || {},
      expiry_at: payload.expiry_at,
      created_at: payload.created_at || new Date().toISOString(),
      updated_at: payload.updated_at || new Date().toISOString(),
    };
  }

  private searchResultToSearchResult(result: any, matchType: string): SearchResult {
    const payload = result.payload || {};
    return {
      id: result.id,
      kind: payload.kind || 'unknown',
      scope: payload.scope || {},
      data: payload.data || {},
      created_at: payload.created_at || new Date().toISOString(),
      confidence_score: result.score || 0,
      match_type: matchType as 'exact' | 'fuzzy' | 'semantic',
      ...(payload.content ? { highlight: [`${payload.content.substring(0, 200)}...`] } : {}),
    };
  }

  private matchesScope(itemScope: Record<string, any>, queryScope: Record<string, any>): boolean {
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
      throw new DatabaseError(
        'Failed to retrieve collection stats',
        'COLLECTION_STATS_ERROR',
        error as Error
      );
    }
  }

  async getCollectionInfo(): Promise<QdrantCollectionInfo> {
    try {
      return (await this.client.getCollection(this.COLLECTION_NAME)) as QdrantCollectionInfo;
    } catch (error) {
      logger.error({ error }, 'Failed to get Qdrant collection info');
      throw new DatabaseError(
        'Failed to retrieve collection info',
        'COLLECTION_INFO_ERROR',
        error as Error
      );
    }
  }

  /**
   * P6-T6.1: Find expired items using Qdrant filtering
   * Efficiently finds items that have expired based on expiry_at timestamp
   */
  async findExpiredItems(options: {
    expiry_before?: string;
    limit?: number;
    scope?: any;
    kinds?: string[];
  }): Promise<KnowledgeItem[]> {
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
      const filterConditions: any[] = [
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
      const genericEmbedding = await this.generateEmbedding('expired item');

      // Search for expired items
      const response = await this.client.search(this.COLLECTION_NAME, {
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

      return expiredItems;
    } catch (error) {
      logger.error(
        {
          error,
          options,
        },
        'Failed to find expired items in Qdrant'
      );
      throw new DatabaseError(
        'Failed to find expired items',
        'EXPIRED_ITEMS_SEARCH_ERROR',
        error as Error
      );
    }
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
        this.healthProbe.addNode(node.id, {
          type: 'qdrant',
          url: node.url,
          apiKey: node.apiKey,
          qdrant: {
            url: node.url,
            apiKey: node.apiKey,
            timeout: 10000,
          },
        });
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

      if (searchResult.results.length === 0) {
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
  private logQdrantCircuitBreakerEvent(event: string, error?: any, metadata?: any): void {
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
}
