/**
 * Enhanced Database Operations Interface
 *
 * Provides missing CRUD operations that are expected by services but not
 * available in the current vector-focused database interfaces.
 *
 * This interface bridges the gap between traditional CRUD expectations
 * and the vector-first Qdrant implementation.
 */

export interface EnhancedDatabaseOperations {
  // Basic CRUD operations (already available in current interfaces)
  findMany: (filter?: unknown) => Promise<unknown[]>;
  findOne: (id: string) => Promise<unknown>;
  create: (data: unknown) => Promise<{ id: string; }>;
  update: (id: string, data: unknown) => Promise<{ id: string; }>;
  delete: (id: string) => Promise<boolean>;

  // Missing operations causing TypeScript errors
  findUnique: (filter: unknown) => Promise<unknown>;
  findFirst: (filter: unknown) => Promise<unknown>;
  findManyWithCount: (filter?: unknown) => Promise<{ items: unknown[]; count: number; }>;
  updateMany: (filter: unknown, data: unknown) => Promise<{ count: number; }>;
  deleteMany: (filter: unknown) => Promise<{ count: number; }>;
  count: (filter?: unknown) => Promise<number>;

  // Aggregate operations for performance optimization
  aggregate: (pipeline: unknown[]) => Promise<unknown[]>;

  // Transaction support
  transaction: (callback: (tx: TransactionInterface) => Promise<unknown>) => Promise<unknown>;
}

export interface TransactionInterface {
  findMany: (filter?: unknown) => Promise<unknown[]>;
  findOne: (id: string) => Promise<unknown>;
  create: (data: unknown) => Promise<{ id: string; }>;
  update: (id: string, data: unknown) => Promise<{ id: string; }>;
  delete: (id: string) => Promise<boolean>;
  updateMany: (filter: unknown, data: unknown) => Promise<{ count: number; }>;
  deleteMany: (filter: unknown) => Promise<{ count: number; }>;
  count: (filter?: unknown) => Promise<number>;
  commit: () => Promise<void>;
  rollback: () => Promise<void>;
}

/**
 * Adapter to convert vector database operations to CRUD operations
 */
export interface CRUDToVectorAdapter {
  // Convert CRUD filter to vector search query
  filterToVectorQuery: (filter: unknown, collection: string) => Promise<SearchQuery>;

  // Convert CRUD data to vector point format
  dataToVectorPoint: (data: unknown, collection: string) => Promise<VectorPoint>;

  // Convert vector search results to CRUD format
  vectorResultsToCRUD: (results: unknown[], collection: string) => Promise<unknown[]>;

  // Collection mapping for different knowledge types
  getCollectionForType: (type: string) => string;
}

export interface SearchQuery {
  vector?: number[];
  text?: string;
  filter?: {
    must?: Array<{
      key: string;
      match?: { value: unknown };
      range?: { gte?: number; lte?: number; };
    }>;
    should?: Array<{
      key: string;
      match?: { value: unknown };
    }>;
    must_not?: Array<{
      key: string;
      match?: { value: unknown };
    }>;
  };
  limit?: number;
  offset?: number;
  with_payload?: boolean | string[];
  with_vector?: boolean;
  score_threshold?: number;
}

export interface VectorPoint {
  id: string;
  vector: number[];
  payload: Record<string, unknown>;
}

/**
 * Enhanced Database Result Types
 */
export interface DatabaseResult<T = unknown> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
  metadata?: {
    count?: number;
    duration?: number;
    query?: string;
  };
}

export interface CountResult {
  count: number;
  filters?: unknown;
}

export interface UpdateResult {
  updated: number;
  matched: number;
  modified: number;
  upserted?: number;
}

export interface DeleteResult {
  deleted: number;
  filters?: unknown;
}