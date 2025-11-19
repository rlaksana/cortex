/**
 * Unified Service Interface Framework
 *
 * Standardized interfaces for all service modules in the Cortex MCP system.
 * Provides consistent patterns for async operations, error handling, and result types.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import type { AuthContext as UnifiedAuthContext } from '../types/auth-unified.js';
import type {
    AnalyticsFilter,
    AnalyticsQuery,
    AnalyticsReport,
    KnowledgeItem,
    SearchResult,
} from '../types/core-interfaces.js';
import type { Scoped } from '../types/index.js';
import type {
    ZAIChatRequest,
    ZAIChatResponse,
    ZAIEventListener,
    ZAIMetrics,
    ZAIStreamChunk
} from '../types/zai-interfaces.js';

// Define Scope type as the Scoped interface for compatibility
type Scope = Scoped['scope'];

// Use unified AuthContext for compatibility
export type AuthContext = UnifiedAuthContext;

// Re-export User type for compatibility
export type { User } from '../types/auth-unified.js';

// ============================================================================
// BASE SERVICE INTERFACES
// ============================================================================

/**
 * Base interface for all service responses
 */
export interface ServiceResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: ServiceError;
  metadata?: ServiceMetadata;
}

/**
 * Standardized service error structure
 */
export interface ServiceError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
  timestamp: string;
  retryable?: boolean;
}

/**
 * Service metadata for tracking and monitoring
 */
export interface ServiceMetadata {
  serviceName: string;
  processingTimeMs: number;
  requestId?: string;
  cached?: boolean;
  source?: string;
  version?: string;
  streaming?: boolean;
}

/**
 * Base interface for all services
 */
export interface IBaseService {
  /**
   * Health check for the service
   */
  healthCheck(): Promise<ServiceResponse<{ status: 'healthy' | 'unhealthy' }>>;

  /**
   * Get service status and metrics
   */
  getStatus(): Promise<ServiceResponse<ServiceStatus>>;

  /**
   * Reset service state (if applicable)
   */
  reset?(): Promise<ServiceResponse<void>>;
}

/**
 * Service status information
 */
export interface ServiceStatus {
  initialized: boolean;
  uptime: number;
  lastCheck: string;
  metrics?: Record<string, unknown>;
}

// ============================================================================
// KNOWLEDGE SERVICE INTERFACES
// ============================================================================

/**
 * Generic knowledge service interface for CRUD operations
 */
export interface IKnowledgeService<TData = unknown, TFilter = unknown> extends IBaseService {
  /**
   * Store a knowledge item
   */
  store(data: TData, scope: Scope): Promise<ServiceResponse<{ id: string }>>;

  /**
   * Retrieve a knowledge item by ID
   */
  get(id: string, scope?: Scope): Promise<ServiceResponse<KnowledgeItem & { data: TData }>>;

  /**
   * Update a knowledge item
   */
  update(id: string, data: Partial<TData>, scope?: Scope): Promise<ServiceResponse<{ id: string }>>;

  /**
   * Soft delete a knowledge item
   */
  delete(id: string, scope?: Scope): Promise<ServiceResponse<{ deleted: boolean }>>;

  /**
   * Search knowledge items
   */
  search(
    query: string,
    filters?: TFilter,
    options?: SearchOptions
  ): Promise<ServiceResponse<SearchResult[]>>;

  /**
   * List knowledge items with optional filtering
   */
  list(filters?: TFilter, options?: ListOptions): Promise<ServiceResponse<Array<KnowledgeItem & { data: TData }>>>;

  /**
   * Count knowledge items matching filters
   */
  count(filters?: TFilter): Promise<ServiceResponse<{ count: number }>>;
}

/**
 * Entity service interface
 */
export interface IEntityService extends IKnowledgeService<EntityData, EntityFilters> {}

/**
 * Relation service interface
 */
export interface IRelationService extends IKnowledgeService<RelationData, RelationFilters> {
  /**
   * Get outgoing relations from an entity
   */
  getOutgoing(
    entityType: string,
    entityId: string,
    relationType?: string
  ): Promise<ServiceResponse<Relation[]>>;

  /**
   * Get incoming relations to an entity
   */
  getIncoming(
    entityType: string,
    entityId: string,
    relationType?: string
  ): Promise<ServiceResponse<Relation[]>>;

  /**
   * Get all relations for an entity (both incoming and outgoing)
   */
  getAll(
    entityType: string,
    entityId: string
  ): Promise<ServiceResponse<{ outgoing: Relation[]; incoming: Relation[] }>>;

  /**
   * Check if a relation exists between two entities
   */
  exists(
    fromType: string,
    fromId: string,
    toType: string,
    toId: string,
    relationType: string
  ): Promise<ServiceResponse<{ exists: boolean }>>;
}

/**
 * Observation service interface
 */
export interface IObservationService
  extends IKnowledgeService<ObservationData, ObservationFilters> {
  /**
   * Add an observation to an entity
   */
  addObservation(data: ObservationData, scope?: Scope): Promise<ServiceResponse<{ id: string }>>;

  /**
   * Get observations for an entity
   */
  getObservations(
    entityType: string,
    entityId: string,
    observationType?: string
  ): Promise<ServiceResponse<Observation[]>>;

  /**
   * Search observations by text
   */
  searchObservations(
    query: string,
    entityTypeFilter?: string,
    limit?: number
  ): Promise<ServiceResponse<Observation[]>>;

  /**
   * Get observation count for an entity
   */
  getObservationCount(
    entityType: string,
    entityId: string
  ): Promise<ServiceResponse<{ count: number }>>;

  /**
   * Get recent observations across all entities
   */
  getRecentObservations(
    limit?: number,
    entityTypeFilter?: string
  ): Promise<ServiceResponse<Observation[]>>;
}

// ============================================================================
// SEARCH SERVICE INTERFACES
// ============================================================================

/**
 * Search service interface
 */
export interface ISearchService extends IBaseService {
  /**
   * Perform search with automatic mode selection
   */
  search(query: SearchQuery): Promise<ServiceResponse<SearchResult[]>>;

  /**
   * Search with specific mode (fast, deep, auto)
   */
  searchByMode(query: SearchQuery): Promise<ServiceResponse<SearchResult[]>>;

  /**
   * Search with explicit mode parameter
   */
  searchWithMode(query: SearchQuery, mode: SearchMode): Promise<ServiceResponse<SearchResult[]>>;

  /**
   * Perform fallback search when primary search fails
   */
  performFallbackSearch(
    parsed: ParsedQuery,
    query: SearchQuery
  ): Promise<ServiceResponse<FallbackSearchResult>>;

  /**
   * Get search metrics and performance data
   */
  getMetrics(): Promise<ServiceResponse<SearchMetrics>>;
}

// ============================================================================
// ANALYTICS SERVICE INTERFACES
// ============================================================================

/**
 * Analytics service interface
 */
export interface IAnalyticsService extends IBaseService {
  /**
   * Execute analytics query
   */
  executeQuery(query: AnalyticsQuery): Promise<ServiceResponse<AnalyticsReport>>;

  /**
   * Generate comprehensive analytics report
   */
  generateComprehensiveReport(filter?: AnalyticsFilter): Promise<ServiceResponse<AnalyticsReport>>;

  /**
   * Get knowledge analytics
   */
  getKnowledgeAnalytics(filter?: AnalyticsFilter): Promise<ServiceResponse<KnowledgeAnalytics>>;

  /**
   * Get relationship analytics
   */
  getRelationshipAnalytics(
    filter?: AnalyticsFilter
  ): Promise<ServiceResponse<RelationshipAnalytics>>;

  /**
   * Get performance analytics
   */
  getPerformanceAnalytics(filter?: AnalyticsFilter): Promise<ServiceResponse<PerformanceAnalytics>>;

  /**
   * Get user behavior analytics
   */
  getUserBehaviorAnalytics(
    filter?: AnalyticsFilter
  ): Promise<ServiceResponse<UserBehaviorAnalytics>>;

  /**
   * Get predictive analytics
   */
  getPredictiveAnalytics(filter?: AnalyticsFilter): Promise<ServiceResponse<PredictiveAnalytics>>;

  /**
   * Get storage analytics
   */
  getStorageAnalytics(filter?: AnalyticsFilter): Promise<ServiceResponse<StorageAnalytics>>;

  /**
   * Clear analytics cache
   */
  clearCache(): Promise<ServiceResponse<void>>;

  /**
   * Get cache statistics
   */
  getCacheStats(): Promise<ServiceResponse<CacheStats>>;
}

// ============================================================================
// MEMORY ORCHESTRATOR INTERFACES
// ============================================================================

/**
 * Memory store orchestrator interface for batch operations
 */
export interface IMemoryStoreOrchestrator extends IBaseService {
  /**
   * Store multiple knowledge items
   */
  storeItems(items: unknown[], authContext?: AuthContext): Promise<ServiceResponse<BatchStorageResult>>;

  /**
   * Get batch storage status
   */
  getBatchStorageStatus(batchId: string): Promise<ServiceResponse<BatchStatus>>;

  /**
   * Cancel batch operation
   */
  cancelBatchOperation(batchId: string): Promise<ServiceResponse<{ cancelled: boolean }>>;
}

/**
 * Memory find orchestrator interface for search operations
 */
export interface IMemoryFindOrchestrator extends IBaseService {
  /**
   * Find knowledge items with advanced filtering
   */
  findItems(query: SearchQuery, authContext?: AuthContext): Promise<ServiceResponse<SearchResult[]>>;

  /**
   * Find similar items using vector similarity
   */
  findSimilarItems(itemId: string, threshold?: number, limit?: number): Promise<ServiceResponse<SearchResult[]>>;

  /**
   * Get find operation metrics
   */
  getFindMetrics(): Promise<ServiceResponse<FindMetrics>>;
}

// ============================================================================
// AI SERVICE INTERFACES
// ============================================================================

/**
 * AI service interface
 */
export interface IAIService extends IBaseService {
  /**
   * Check if service is available
   */
  isAvailable(): Promise<ServiceResponse<{ available: boolean }>>;

  /**
   * Get service status
   */
  getServiceStatus(): Promise<ServiceResponse<AIServiceStatus>>;

  /**
   * Get service metrics
   */
  getMetrics(): Promise<ServiceResponse<ZAIMetrics>>;

  /**
   * Reset metrics
   */
  reset(): Promise<ServiceResponse<void>>;

  /**
   * Add event listener
   */
  addEventListener(listener: ZAIEventListener): ServiceResponse<void>;

  /**
   * Remove event listener
   */
  removeEventListener(listener: ZAIEventListener): ServiceResponse<void>;
}

/**
 * ZAI Client service interface
 */
export interface IZAIClientService extends IAIService {
  /**
   * Generate chat completion
   */
  generateCompletion(request: ZAIChatRequest): Promise<ServiceResponse<ZAIChatResponse>>;

  /**
   * Generate streaming completion
   */
  generateStreamingCompletion(request: ZAIChatRequest): Promise<AsyncGenerator<ZAIStreamChunk>>;
}

/**
 * Embedding service interface
 */
export interface IEmbeddingService extends IAIService {
  /**
   * Generate embedding for a single text
   */
  generateEmbedding(request: EmbeddingRequest | string): Promise<ServiceResponse<EmbeddingResult>>;

  /**
   * Generate embedding for a single text with chunking context
   */
  generateEmbeddingWithContext(
    request: EmbeddingRequest | string,
    context?: EmbeddingContext
  ): Promise<ServiceResponse<EmbeddingResult>>;

  /**
   * Generate embeddings for multiple texts in batch
   */
  generateBatchEmbeddings(
    request: BatchEmbeddingRequest
  ): Promise<ServiceResponse<EmbeddingResult[]>>;

  /**
   * Get service statistics
   */
  getStats(): Promise<ServiceResponse<EmbeddingStats>>;

  /**
   * Clear cache
   */
  clearCache(): Promise<ServiceResponse<void>>;

  /**
   * Warm up cache with common embeddings
   */
  warmupCache(commonTexts: string[]): Promise<ServiceResponse<void>>;

  /**
   * Estimate cost for embedding generation
   */
  estimateCost(
    textCount: number,
    charactersPerText?: number
  ): Promise<ServiceResponse<CostEstimate>>;
}

// ============================================================================
// COMMON TYPE DEFINITIONS
// ============================================================================

/**
 * Search options
 */
export interface SearchOptions {
  limit?: number;
  offset?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
  includeMetadata?: boolean;
}

/**
 * List options
 */
export interface ListOptions {
  limit?: number;
  offset?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
  includeDeleted?: boolean;
}

// Import canonical SearchQuery from core-interfaces to avoid duplication
import type { SearchQuery as CoreSearchQuery } from '../types/core-interfaces.js';

// Re-export for backward compatibility and to provide a single source of truth
export type SearchQuery = CoreSearchQuery;

/**
 * Search modes
 */
export type SearchMode = 'auto' | 'fast' | 'deep';

/**
 * Parsed query interface
 */
export interface ParsedQuery {
  original: string;
  terms: string[];
  filters: Record<string, unknown>;
  mode: SearchMode;
}

/**
 * Fallback search result
 */
export interface FallbackSearchResult {
  results: SearchResult[];
  totalCount: number;
  strategy: string;
  qualityMetrics: SearchMetrics;
}

/**
 * Search metrics
 */
export interface SearchMetrics {
  p95Latency: number;
  averageLatency: number;
  totalQueries: number;
  successRate: number;
  cacheHitRate: number;
}

/**
 * Cache statistics
 */
export interface CacheStats {
  size: number;
  hitRate: number;
}

// ============================================================================
// KNOWLEDGE TYPE DEFINITIONS
// ============================================================================

/**
 * Entity data interface
 */
export interface EntityData {
  entity_type: string;
  name: string;
  data: Record<string, unknown>;
}

/**
 * Entity filters
 */
export interface EntityFilters {
  entity_type?: string;
  name?: string;
  scope?: Scope;
  limit?: number;
}

/**
 * Relation data interface
 */
export interface RelationData {
  from_entity_type: string;
  from_entity_id: string;
  to_entity_type: string;
  to_entity_id: string;
  relation_type: string;
  metadata?: Record<string, unknown>;
}

/**
 * Relation filters
 */
export interface RelationFilters {
  from_entity_type?: string;
  to_entity_type?: string;
  relation_type?: string;
  scope?: Scope;
}

/**
 * Relation interface
 */
export interface Relation {
  id: string;
  from_entity_type: string;
  from_entity_id: string;
  to_entity_type: string;
  to_entity_id: string;
  relation_type: string;
  metadata?: Record<string, unknown>;
  created_at: Date;
}

/**
 * Observation data interface
 */
export interface ObservationData {
  entity_type: string;
  entity_id: string;
  observation: string;
  observation_type?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Observation filters
 */
export interface ObservationFilters {
  entity_type?: string;
  entity_id?: string;
  observation_type?: string;
  scope?: Scope;
}

/**
 * Observation interface
 */
export interface Observation {
  id: string;
  entity_type: string;
  entity_id: string;
  observation: string;
  observation_type?: string;
  metadata?: Record<string, unknown>;
  created_at: Date;
}

// ============================================================================
// ANALYTICS TYPE DEFINITIONS
// ============================================================================

/**
 * Analytics type interfaces (re-exported from core-interfaces)
 */
import type {
    KnowledgeAnalytics,
    PerformanceAnalytics,
    PredictiveAnalytics,
    RelationshipAnalytics,
    StorageAnalytics,
    UserBehaviorAnalytics,
} from '../types/core-interfaces.js';

export type {
    KnowledgeAnalytics,
    PerformanceAnalytics,
    PredictiveAnalytics,
    RelationshipAnalytics,
    StorageAnalytics,
    UserBehaviorAnalytics
};

// ============================================================================
// AI SERVICE TYPE DEFINITIONS
// ============================================================================

/**
 * AI service status
 */
export interface AIServiceStatus {
  status: 'healthy' | 'degraded' | 'down';
  lastCheck: string;
  responseTime: number;
  errorRate: number;
  circuitBreakerState: 'closed' | 'open' | 'half-open';
  consecutiveFailures: number;
  uptime: number;
}

/**
 * AI event
 */


// ZAIEvent is imported from '../types/zai-interfaces.js'

/**
 * ZAI interfaces (re-exported from zai-interfaces)
 */
export type {
    ZAIChatRequest,
    ZAIChatResponse,
    ZAIErrorResponse,
    ZAIStreamChunk
} from '../types/zai-interfaces.js';

/**
 * Embedding request interface
 */
export interface EmbeddingRequest {
  text: string;
  metadata?: Record<string, unknown>;
  cacheKey?: string;
  priority?: 'high' | 'normal' | 'low';
}

/**
 * Embedding context
 */
export interface EmbeddingContext {
  is_chunk?: boolean;
  chunk_index?: number;
  total_chunks?: number;
  parent_id?: string;
  extracted_title?: string;
}

/**
 * Embedding result interface
 */
export interface EmbeddingResult {
  vector: number[];
  model: string;
  usage: {
    prompt_tokens: number;
    total_tokens: number;
  };
  cached: boolean;
  processingTime: number;
  metadata?: Record<string, unknown>;
}

/**
 * Batch embedding request
 */
export interface BatchEmbeddingRequest {
  texts: string[];
  metadata?: Record<string, unknown>[];
  priority?: 'high' | 'normal' | 'low';
}

/**
 * Embedding statistics
 */
export interface EmbeddingStats {
  totalRequests: number;
  cacheHits: number;
  cacheMisses: number;
  averageProcessingTime: number;
  totalTokensUsed: number;
  errors: number;
  model: string;
  cacheSize: number;
  cacheHitRate: number;
}

/**
 * Cost estimate
 */
export interface CostEstimate {
  requests: number;
  tokens: number;
  estimatedCostUSD: number;
}

// ============================================================================
// MEMORY ORCHESTRATOR TYPE DEFINITIONS
// ============================================================================

/**
 * Batch storage result
 */
export interface BatchStorageResult {
  batchId: string;
  items: ItemResult[];
  summary: BatchSummary;
  processingTimeMs: number;
  duplicateCount: number;
}

/**
 * Batch status information
 */
export interface BatchStatus {
  batchId: string;
  status: 'pending' | 'processing' | 'completed' | 'failed' | 'cancelled';
  totalItems: number;
  processedItems: number;
  errors: number;
  startTime: string;
  estimatedCompletion?: string;
}

/**
 * Find operation metrics
 */
export interface FindMetrics {
  totalQueries: number;
  averageLatency: number;
  successRate: number;
  cacheHitRate: number;
  vectorSearchUsage: number;
  keywordSearchUsage: number;
}

/**
 * Item result for batch operations
 */
export interface ItemResult {
  input_index: number;
  status: 'stored' | 'updated' | 'skipped_dedupe' | 'error';
  id?: string;
  error?: string;
  duplicate_of?: string;
  kind: string;
}

/**
 * Batch summary for operations
 */
export interface BatchSummary {
  total: number;
  stored: number;
  updated: number;
  skipped: number;
  errors: number;
  duplicates: number;
  processing_time_ms: number;
}
