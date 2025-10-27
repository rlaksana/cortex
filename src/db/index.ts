/**
 * Database Module Index
 *
 * Central exports for all database components, including adapters,
 * interfaces, factories, and types. Provides a clean API for
 * consuming the database functionality.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

// === Core Adapters ===
export { QdrantAdapter } from './adapters/qdrant-adapter.js';

// === Factory ===
export { DatabaseFactory, databaseFactory } from './factory/database-factory.js';

// === Unified Database Layer ===
export {
  QdrantOnlyDatabaseLayer as UnifiedDatabaseLayer,
  createQdrantOnlyDatabase as createUnifiedDatabaseLayer,
} from './unified-database-layer-v2.js';

// === Legacy Compatibility (deprecated) ===
export { UnifiedDatabaseLayer as LegacyUnifiedDatabaseLayer } from './unified-database-layer.js';

// === Interfaces ===

export type {
  IVectorAdapter,
  VectorConfig,
  SearchOptions as VectorSearchOptions,
  StoreOptions as VectorStoreOptions,
  DeleteOptions as VectorDeleteOptions,
} from './interfaces/vector-adapter.interface.js';

export type {
  IDatabaseFactory,
  DatabaseFactoryConfig,
  DatabaseType,
  DatabaseAdapters,
  AdapterCapabilities,
} from './interfaces/database-factory.interface.js';

// === Database Interface (Legacy) ===
export type {
  IDatabase,
  IDatabaseAdapter,
  DatabaseConfig as LegacyDatabaseConfig,
  DatabaseMetrics,
  SearchOptions as LegacySearchOptions,
  StoreOptions as LegacyStoreOptions,
  DeleteOptions as LegacyDeleteOptions,
} from './database-interface.js';

// === Types ===
export type {
  // Core types
  KnowledgeItem,
  StoreResult,
  StoreError,
  SearchResult,
  SearchQuery,
  MemoryStoreResponse,
  MemoryFindResponse,
  AutonomousContext,

  // Database types
  DatabaseConfig,
  FallbackConfig,
  OperationResult,
  BatchOperationResult,
  QueryBuilder,
  TransactionOptions,
  Transaction,
  PoolStats,
  ConnectionPool,
  Migration,
  MigrationOptions,
  BackupOptions,
  BackupResult,
  PerformanceMetrics,
  HealthCheckResult,
  DatabaseOperation,
  DatabaseOperations,
  DatabaseEvent,
  QueryEvent,
  ConnectionEvent,
  TransactionEvent,
  DatabaseEventHandler,
  ValidationResult,
  ConfigValidator,
  IndexDefinition,
  ColumnDefinition,
  TableDefinition,
  EnhancedSearchResult,
  PaginationOptions,
  PaginatedResult,

  // Utility types
  DeepPartial,
  RequiredFields,
  OptionalFields,

  // Type guards
  isDatabaseError,
  isConnectionError,
  isValidationError,
  isNotFoundError,
  isDuplicateError,
} from './types/database-types.js';

// === Error Classes ===
export {
  DatabaseError,
  ConnectionError,
  ValidationError,
  NotFoundError,
  DuplicateError,
} from './types/database-types.js';

// === Re-export errors from legacy interface ===
export {
  DatabaseError as LegacyDatabaseError,
  ConnectionError as LegacyConnectionError,
  ValidationError as LegacyValidationError,
  NotFoundError as LegacyNotFoundError,
  DuplicateError as LegacyDuplicateError,
  EmbeddingError,
  CollectionError,
  VectorError,
} from './database-interface.js';

// === Factory Errors ===
export {
  DatabaseFactoryError,
  ConfigurationError,
  AdapterCreationError,
  UnsupportedDatabaseError,
} from './interfaces/database-factory.interface.js';

// === Utility Functions ===

/**
 * Create a database instance with environment configuration
 */
export async function createDatabaseFromEnvironment(): Promise<UnifiedDatabaseLayer> {
  const { DatabaseFactory } = await import('./factory/database-factory.js');
  const factory = new DatabaseFactory();
  const adapters = await DatabaseFactory.createFromEnvironment();

  return new UnifiedDatabaseLayer({
    type: adapters.type,
    qdrant: adapters.config.qdrant
      ? {
          url: adapters.config.qdrant?.url,
          apiKey: adapters.config.qdrant?.apiKey,
          vectorSize: adapters.config.qdrant?.vectorSize,
          distance: adapters.config.qdrant?.distance,
          connectionTimeout: adapters.config.qdrant?.connectionTimeout,
          maxConnections: adapters.config.qdrant?.maxConnections,
          logQueries: adapters.config.qdrant?.logQueries,
        }
      : undefined,
  });
}

/**
 * Validate database configuration
 */
export async function validateDatabaseConfig(config: DatabaseConfig): Promise<ValidationResult> {
  const { DatabaseFactory } = await import('./factory/database-factory.js');
  const factory = new DatabaseFactory();

  const factoryConfig: DatabaseFactoryConfig = {
    type: config.type,
    qdrant: config.qdrant
      ? {
          type: 'qdrant',
          url: config.qdrant.url,
          apiKey: config.qdrant.apiKey,
          vectorSize: config.qdrant.vectorSize,
          distance: config.qdrant.distance,
          logQueries: config.qdrant.logQueries,
          connectionTimeout: config.qdrant.connectionTimeout,
          maxConnections: config.qdrant.maxConnections,
        }
      : undefined,
    fallback: config.fallback,
  };

  return await factory.validateConfig(factoryConfig);
}

/**
 * Test database connectivity
 */
export async function testDatabaseConnectivity(config: DatabaseConfig): Promise<{
  qdrant: boolean;
  overall: boolean;
}> {
  const { DatabaseFactory } = await import('./factory/database-factory.js');
  const factory = new DatabaseFactory();

  const results = {
    qdrant: false,
    overall: false,
  };

  try {
    if (config.qdrant) {
      results.qdrant = await factory.testConnection('qdrant', config.qdrant);
    }

    results.overall = results.qdrant;
  } catch (error) {
    console.error('Database connectivity test failed:', error);
  }

  return results;
}

/**
 * Get database capabilities for a given type
 */
export async function getDatabaseCapabilities(type: DatabaseType): Promise<AdapterCapabilities> {
  const { DatabaseFactory } = await import('./factory/database-factory.js');
  const factory = new DatabaseFactory();
  return factory.getCapabilities(type);
}

/**
 * Create a vector adapter directly
 */
export async function createVectorAdapter(config: VectorConfig): Promise<IVectorAdapter> {
  const { DatabaseFactory } = await import('./factory/database-factory.js');
  const factory = new DatabaseFactory();
  return await factory.createVectorAdapter(config);
}

// === Default Export ===
export default {
  // Adapters
  QdrantAdapter,

  // Factory
  DatabaseFactory,
  databaseFactory,

  // Unified Layer
  UnifiedDatabaseLayer,
  createUnifiedDatabaseLayer,
  createDatabaseFromEnvironment,

  // Legacy (deprecated)
  LegacyUnifiedDatabaseLayer,

  // Utilities
  validateDatabaseConfig,
  testDatabaseConnectivity,
  getDatabaseCapabilities,
  createVectorAdapter,

  // Types (re-exported)
  // Note: Types are available via named exports above
};
