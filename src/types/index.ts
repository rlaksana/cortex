/**
 * Central Type Exports for Cortex MCP System
 *
 * This module provides a centralized export point for all critical types
 * to ensure consistent type imports across the codebase and resolve
 * interface mismatches.
 */

// Core Knowledge Types
export type { KnowledgeItem } from './core-interfaces.js';
export type { KnowledgeItemForStorage, AutonomousContext, SearchResult, SearchQuery } from './core-interfaces.js';
export type { ItemResult, BatchSummary, MemoryStoreResponse, MemoryFindResponse } from './core-interfaces.js';
export type { MemoryStoreRequest, MemoryFindRequest, DeleteRequest } from './core-interfaces.js';
export type { ValidationService, DeduplicationService, SimilarityService } from './core-interfaces.js';
export type { BusinessValidator, ValidatorRegistry, ValidationResult } from './core-interfaces.js';

// API and Service Types
export type { ApiEndpoint, ApiRequest, ApiParameter, ValidationRule } from './api-interfaces.js';
export type { ApiMiddleware, AuthenticationMethod, ApiUser, RateLimitConfig } from './api-interfaces.js';
export type { ServiceEndpoint, LoadBalancingStrategy } from './api-interfaces.js';
export type { ApiResponse as ApiContractResponse } from './api-interfaces.js';

// Contract Types
export type { StoreResult, StoreError, CortexResponseMeta, CortexOperation } from './contracts.js';
export type { PerformanceMetrics } from './contracts.js';

// Error Handling Types
export type { ValidationError, ErrorCategory } from './error-handling-interfaces.js';
export type { ApiError } from './api-interfaces.js';

// Database Types
export type { IDatabase } from '../db/database-interface.js';

// Knowledge Data Types
export type { KnowledgeItem as KnowledgeData } from './core-interfaces.js';

// Auth Types
export type { AuthContext } from './auth-types.js';

// Standard response types
export interface SuccessResponse<T = unknown> {
  success: true;
  data: T;
  message?: string;
}

export interface ErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    details?: unknown;
  };
}

export type StandardApiResponse<T = unknown> = SuccessResponse<T> | ErrorResponse;

// Common service patterns
export interface ServiceConfig {
  timeout?: number;
  retries?: number;
  enableLogging?: boolean;
}

export interface ServiceMetrics {
  operationCount: number;
  successCount: number;
  errorCount: number;
  averageResponseTime: number;
  lastUpdated: Date;
}

// Common field types
export interface Timestamped {
  created_at: string;
  updated_at?: string;
}

export interface Identifiable {
  id: string;
}

export interface Scoped {
  scope: {
    project?: string;
    branch?: string;
    org?: string;
  };
}

export interface Metadata {
  tags?: Record<string, string>;
  version?: string;
  source?: string;
}

// Common search types
export interface SearchOptions {
  limit?: number;
  offset?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
  includeMetadata?: boolean;
}

export interface SearchFilters {
  types?: string[];
  scope?: Scoped['scope'];
  dateRange?: {
    startDate: string;
    endDate: string;
  };
  tags?: Record<string, string>;
}

// Re-export common utility types for convenience
export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;
export type RequiredBy<T, K extends keyof T> = T & Required<Pick<T, K>>;
export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};