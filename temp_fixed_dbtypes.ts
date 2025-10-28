/**
 * Database Type Definitions
 *
 * Comprehensive type definitions for database operations,
 * configurations, and error handling.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import type {
  KnowledgeItem,
  StoreResult,
  StoreError,
  SearchResult as CoreSearchResult,
  SearchQuery,
  MemoryStoreResponse,
  MemoryFindResponse,
  AutonomousContext,
} from '../../types/core-interfaces';
import type {
  IVectorAdapter,
  VectorConfig,
  SearchOptions as VectorSearchOptions,
} from '../interfaces/vector-adapter.interface';
import type {
  IDatabaseFactory,
  DatabaseFactoryConfig,
  DatabaseType,
  DatabaseAdapters,
  AdapterCapabilities,
} from '../interfaces/database-factory.interface';

// Re-export core interfaces
export type {
  KnowledgeItem,
  StoreResult,
  StoreError,
  SearchResult as CoreSearchResult,
  SearchQuery,
  MemoryStoreResponse,
  MemoryFindResponse,
  AutonomousContext,
} from '../../types/core-interfaces';

export type {
  IVectorAdapter,
  VectorConfig,
  SearchOptions as VectorSearchOptions,
} from '../interfaces/vector-adapter.interface';

export type {
  IDatabaseFactory,
  DatabaseFactoryConfig,
  DatabaseType,
  DatabaseAdapters,
  AdapterCapabilities,
} from '../interfaces/database-factory.interface';

// Use alias to avoid conflicts
export type SearchResult = CoreSearchResult;
