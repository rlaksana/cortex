// PHASE 2.1 RECOVERY: Contracts interface synchronization complete
// Status: TypeScript recovery in progress - @ts-nocheck removed systematically
// Recovery Date: 2025-11-14T16:35:00+07:00 (Asia/Jakarta)
// Recovery Method: Sequential file-by-file approach with quality gates
// Dependencies: 18+ services depend on contract interfaces

/**
 * Unified contracts for Cortex MCP system
 * Centralized to ensure consistency across all services
 */

// Define KnowledgeItem interface directly to avoid circular references
export interface KnowledgeItem {
  id?: string;
  kind: string;
  content?: string;
  scope: {
    project?: string;
    branch?: string;
    org?: string;
  };
  data: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
  expiry_at?: string;
}

// Define StoreResult interface directly to avoid circular references
export interface StoreResult {
  success?: boolean;
  id?: string;
  error?: string;
  message?: string;
  existing_id?: string;
  duplicate_of?: string;
  status?:
    | 'stored'
    | 'skipped_dedupe'
    | 'business_rule_blocked'
    | 'validation_error'
    | 'inserted'
    | 'updated'
    | 'deleted';
  kind?: string;
  created_at?: string;
}

// Define StoreError interface directly to avoid circular references
export interface StoreError {
  index?: number;
  code?: string;
  error_code?: string;
  message: string;
  field?: string;
  item?: unknown;
}

// Unified response metadata contract
export interface CortexResponseMeta {
  // Core operational metadata
  strategy: string;
  vector_used: boolean;
  degraded: boolean;
  source: string;
  execution_time_ms?: number;
  confidence_score?: number;

  // Truncation metadata
  truncated: boolean;
  truncation_details?: Array<{
    result_index: number;
    result_id: string;
    original_length: number;
    truncated_length: number;
    truncation_type: 'character' | 'token' | 'both';
    limit_applied: number;
    strategy: string;
    content_type?: string;
  }>;
  total_chars_removed?: number;
  total_tokens_removed?: number;
  warnings?: string[];
}

// MCP tool operation types
export type CortexOperation =
  | 'store'
  | 'find'
  | 'validate'
  | 'purge'
  | 'cleanup'
  | 'dedupe'
  | 'rate_limit'
  | 'truncation'
  | 'chunking'
  | 'dedupe_hits'
  | 'error'
  | 'insight_generation'
  | 'insight_generation_summary';

// Performance metrics type
export interface PerformanceMetrics {
  duration_ms: number;
  operation: CortexOperation;
  success: boolean;
  error_code?: string;
  metadata?: Record<string, unknown>;
}
