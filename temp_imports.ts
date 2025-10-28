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

// Re-export core interfaces
export type {
  KnowledgeItem,
  StoreResult,
  StoreError,
  SearchResult,
  SearchQuery,
  MemoryStoreResponse,
  MemoryFindResponse,
  AutonomousContext,
} from '../../types/core-interfaces';

// PostgreSQL interfaces and types removed - PostgreSQL is no longer supported
// Only Qdrant vector database interfaces are available in this Qdrant-only architecture

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
