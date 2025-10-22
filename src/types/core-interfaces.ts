/**
 * Core interfaces for the Cortex Memory MCP system
 * Provides contracts for knowledge management operations
 */

export interface KnowledgeItem {
  id?: string;
  kind: string;
  scope: {
    project?: string;
    branch?: string;
    org?: string;
  };
  data: Record<string, any>;
  created_at?: string;
  updated_at?: string;
}

export interface StoreResult {
  id: string;
  status: 'inserted' | 'updated' | 'skipped_dedupe' | 'deleted';
  kind: string;
  created_at: string;
}

export interface StoreError {
  index: number;
  error_code: string;
  message: string;
  field?: string;
}

export interface AutonomousContext {
  action_performed: 'created' | 'updated' | 'deleted' | 'skipped' | 'batch';
  similar_items_checked: number;
  duplicates_found: number;
  contradictions_detected: boolean;
  recommendation: string;
  reasoning: string;
  user_message_suggestion: string;
}

export interface SearchResult {
  id: string;
  kind: string;
  scope: Record<string, any>;
  data: Record<string, any>;
  created_at: string;
  confidence_score: number;
  match_type: 'exact' | 'fuzzy' | 'semantic';
}

export interface SearchQuery {
  query: string;
  scope?: {
    project?: string;
    branch?: string;
    org?: string;
  };
  types?: string[];
  mode?: 'auto' | 'fast' | 'deep';
  limit?: number;
  top_k?: number;
}

export interface MemoryStoreResponse {
  stored: StoreResult[];
  errors: StoreError[];
  autonomous_context: AutonomousContext;
}

export interface MemoryFindResponse {
  results: SearchResult[];
  total_count: number;
  autonomous_context: {
    search_mode_used: string;
    results_found: number;
    confidence_average: number;
    user_message_suggestion: string;
  };
}

/**
 * Repository interface for knowledge persistence operations
 */
export interface KnowledgeRepository {
  store(item: KnowledgeItem): Promise<StoreResult>;
  update(id: string, item: Partial<KnowledgeItem>): Promise<StoreResult>;
  delete(id: string): Promise<boolean>;
  findById(id: string): Promise<KnowledgeItem | null>;
  findSimilar(item: KnowledgeItem, threshold?: number): Promise<KnowledgeItem[]>;
}

/**
 * Service interface for search operations
 */
export interface SearchService {
  search(query: SearchQuery): Promise<MemoryFindResponse>;
  validateQuery(query: SearchQuery): Promise<boolean>;
}

/**
 * Service interface for validation operations
 */
export interface ValidationService {
  validateStoreInput(items: unknown[]): Promise<{ valid: boolean; errors: StoreError[] }>;
  validateFindInput(input: unknown): Promise<{ valid: boolean; errors: string[] }>;
  validateKnowledgeItem(item: KnowledgeItem): Promise<{ valid: boolean; errors: string[] }>;
}

/**
 * Service interface for deduplication operations
 */
export interface DeduplicationService {
  checkDuplicates(items: KnowledgeItem[]): Promise<{ duplicates: KnowledgeItem[]; originals: KnowledgeItem[] }>;
  removeDuplicates(items: KnowledgeItem[]): Promise<KnowledgeItem[]>;
}

/**
 * Service interface for similarity detection
 */
export interface SimilarityService {
  findSimilar(item: KnowledgeItem, threshold?: number): Promise<KnowledgeItem[]>;
  calculateSimilarity(item1: KnowledgeItem, item2: KnowledgeItem): Promise<number>;
}

/**
 * Service interface for audit logging
 */
export interface AuditService {
  logOperation(operation: string, data: Record<string, any>): Promise<void>;
  logAccess(resource: string, userId?: string): Promise<void>;
  logError(error: Error, context: Record<string, any>): Promise<void>;
}

/**
 * Memory store request interface
 */
export interface MemoryStoreRequest {
  items: any[];
}

/**
 * Memory find request interface
 */
export interface MemoryFindRequest {
  query: string;
  scope?: {
    project?: string;
    branch?: string;
    org?: string;
  };
  types?: string[];
  mode?: 'auto' | 'fast' | 'deep';
  limit?: number;
}

/**
 * Delete request interface
 */
export interface DeleteRequest {
  id: string;
  kind?: string;
  scope?: {
    project?: string;
    branch?: string;
    org?: string;
  };
  cascade_relations?: boolean;
}

/**
 * Smart find request interface
 */
export interface SmartFindRequest {
  query: string;
  scope?: Record<string, unknown>;
  types?: string[];
  top_k?: number;
  mode?: 'auto' | 'fast' | 'deep';
  enable_auto_fix?: boolean;
  return_corrections?: boolean;
  max_attempts?: number;
  timeout_per_attempt_ms?: number;
}

/**
 * Smart find result interface
 */
export interface SmartFindResult {
  hits: Array<{
    kind: string;
    id: string;
    title: string;
    snippet: string;
    score: number;
    scope?: Record<string, unknown>;
    updated_at?: string;
    route_used: string;
    confidence: number;
  }>;
  suggestions: string[];
  autonomous_metadata: {
    strategy_used: 'fast' | 'deep' | 'fast_then_deep_fallback';
    mode_requested: string;
    mode_executed: string;
    confidence: 'high' | 'medium' | 'low';
    total_results: number;
    avg_score: number;
    fallback_attempted: boolean;
    recommendation: string;
    user_message_suggestion: string;
  };
  corrections?: {
    original_query: string;
    final_query: string;
    attempts: Array<{
      attempt_number: number;
      query: string;
      mode: string;
      sanitization_level?: string;
      error?: string;
      success: boolean;
      timestamp: number;
      duration_ms: number;
    }>;
    transformations: string[];
    total_attempts: number;
    auto_fixes_applied: string[];
    patterns_detected: string[];
    final_sanitization_level: string;
    recommendation: string;
  };
  debug?: Record<string, unknown>;
  graph?: any;
}