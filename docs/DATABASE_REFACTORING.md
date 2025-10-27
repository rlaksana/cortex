# Database Architecture Refactoring - Migration Guide

## Overview

This document describes the comprehensive refactoring of the Cortex MCP database architecture from a monolithic design to a clean, modular, and maintainable system following SOLID principles.

## Problems Addressed

### 1. Interface-Implementation Mismatch
- **Before**: `UnifiedDatabaseLayer` had 1000+ lines mixing PostgreSQL and Qdrant operations
- **After**: Clear separation with dedicated interfaces (`IPostgreSQLAdapter`, `IVectorAdapter`)

### 2. Monolithic Classes
- **Before**: Single class handling connection management, CRUD, search, UUID generation, query analysis
- **After**: Focused adapters with single responsibilities

### 3. Type Safety Issues
- **Before**: Extensive use of `any` types, inconsistent method signatures
- **After**: Full TypeScript typing with proper interfaces and generic types

### 4. SOLID Violations
- **Before**: Violated Single Responsibility, Open/Closed, Liskov Substitution, Interface Segregation, and Dependency Inversion principles
- **After**: Clean architecture following all SOLID principles

## New Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                UnifiedDatabaseLayer (Facade)                │
│  ┌─────────────────┐              ┌──────────────────────┐ │
│  │   PostgreSQL    │              │      Qdrant          │ │
│  │    Adapter      │              │      Adapter         │ │
│  └─────────────────┘              └──────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────────────┐
                    │ DatabaseFactory │
                    └─────────────────┘
```

## Components

### 1. Interfaces

#### IPostgreSQLAdapter
```typescript
interface IPostgreSQLAdapter {
  // Lifecycle
  initialize(): Promise<void>;
  healthCheck(): Promise<boolean>;
  getMetrics(): Promise<DatabaseMetrics>;
  close(): Promise<void>;

  // CRUD Operations
  create<T>(table: string, data: Record<string, any>): Promise<T>;
  update<T>(table: string, where: Record<string, any>, data: Record<string, any>): Promise<T>;
  delete<T>(table: string, where: Record<string, any>): Promise<T>;
  find<T>(table: string, where?: Record<string, any>, options?: QueryOptions): Promise<T[]>;

  // PostgreSQL-specific
  fullTextSearch(options: FullTextSearchOptions): Promise<SearchResult[]>;
  generateUUID(options?: UUIDGenerationOptions): Promise<string>;
  explainQuery(sql: string, params?: any[], options?: ExplainOptions): Promise<ExplainResult>;
}
```

#### IVectorAdapter
```typescript
interface IVectorAdapter {
  // Lifecycle
  initialize(): Promise<void>;
  healthCheck(): Promise<boolean>;
  getMetrics(): Promise<DatabaseMetrics>;
  close(): Promise<void>;

  // Knowledge Operations
  store(items: KnowledgeItem[], options?: StoreOptions): Promise<MemoryStoreResponse>;
  search(query: SearchQuery, options?: SearchOptions): Promise<MemoryFindResponse>;
  semanticSearch(query: string, options?: SearchOptions): Promise<SearchResult[]>;
  vectorSearch(embedding: number[], options?: SearchOptions): Promise<SearchResult[]>;

  // Vector Operations
  generateEmbedding(content: string): Promise<number[]>;
  findSimilar(item: KnowledgeItem, threshold?: number, options?: SearchOptions): Promise<SearchResult[]>;
}
```

### 2. Adapters

#### PostgreSQLAdapter
- Handles all PostgreSQL-specific operations
- Implements full-text search with tsvector/tsquery
- UUID generation (v4 and v7)
- Query execution plan analysis
- JSON Path operations
- Array operations

#### QdrantAdapter
- Focuses only on vector operations
- Semantic search and similarity
- Embedding generation
- Vector storage and retrieval
- Collection management

### 3. Factory Pattern

#### DatabaseFactory
```typescript
class DatabaseFactory implements IDatabaseFactory {
  async create(config: DatabaseFactoryConfig): Promise<DatabaseAdapters>;
  async createPostgreSQLAdapter(config: PostgreSQLConfig): Promise<IPostgreSQLAdapter>;
  async createVectorAdapter(config: VectorConfig): Promise<IVectorAdapter>;
  async validateConfig(config: DatabaseFactoryConfig): Promise<ValidationResult>;
  getCapabilities(type: DatabaseType): AdapterCapabilities>;
}
```

### 4. Unified Facade

#### UnifiedDatabaseLayer
- Thin facade that delegates to appropriate adapters
- Maintains backward compatibility
- Handles routing of operations to correct adapter
- Provides unified error handling and logging

## Migration Guide

### Step 1: Update Imports

**Before:**
```typescript
import { UnifiedDatabaseLayer, database } from './db/unified-database-layer.js';
```

**After:**
```typescript
import {
  UnifiedDatabaseLayer,
  createUnifiedDatabaseLayer,
  createDatabaseFromEnvironment
} from './db/index.js';
```

### Step 2: Update Configuration

**Before:**
```typescript
const db = new UnifiedDatabaseLayer({
  postgresConnectionString: process.env.DATABASE_URL,
  qdrantUrl: process.env.QDRANT_URL,
  // ... other config
});
```

**After:**
```typescript
// Option 1: Use environment defaults
const db = await createDatabaseFromEnvironment();

// Option 2: Custom configuration
const db = createUnifiedDatabaseLayer({
  type: 'hybrid',
  postgres: {
    connectionString: process.env.DATABASE_URL,
    maxConnections: 10,
    logQueries: false
  },
  qdrant: {
    url: process.env.QDRANT_URL,
    apiKey: process.env.QDRANT_API_KEY,
    vectorSize: 1536
  }
});
```

### Step 3: Update Usage Patterns

**Before:**
```typescript
await db.initialize();
const results = await db.fullTextSearch({ query: 'example', max_results: 10 });
```

**After:**
```typescript
await db.initialize();
const results = await db.fullTextSearch({ query: 'example', max_results: 10 });
// API remains the same for backward compatibility
```

### Step 4: Direct Adapter Usage (Advanced)

```typescript
import { createPostgreSQLAdapter, createVectorAdapter } from './db/index.js';

// Direct PostgreSQL usage
const postgres = await createPostgreSQLAdapter({
  postgresConnectionString: process.env.DATABASE_URL,
  logQueries: true
});

// Direct vector usage
const vector = await createVectorAdapter({
  url: process.env.QDRANT_URL,
  apiKey: process.env.QDRANT_API_KEY,
  vectorSize: 1536
});
```

## Configuration Options

### Database Types

1. **postgresql**: PostgreSQL only
2. **qdrant**: Vector database only
3. **hybrid**: Both PostgreSQL and Qdrant (recommended)

### Environment Variables

```bash
# PostgreSQL
DATABASE_URL=postgresql://user:password@localhost:5432/database

# Qdrant
QDRANT_URL=http://localhost:6333
QDRANT_API_KEY=your-api-key

# General
NODE_ENV=development
LOG_LEVEL=debug
```

## Testing the Migration

### 1. Validate Configuration
```typescript
import { validateDatabaseConfig } from './db/index.js';

const validation = await validateDatabaseConfig({
  type: 'hybrid',
  postgres: { /* config */ },
  qdrant: { /* config */ }
});

if (!validation.valid) {
  console.error('Configuration errors:', validation.errors);
}
```

### 2. Test Connectivity
```typescript
import { testDatabaseConnectivity } from './db/index.js';

const connectivity = await testDatabaseConnectivity(config);
console.log('PostgreSQL:', connectivity.postgresql);
console.log('Qdrant:', connectivity.qdrant);
```

### 3. Check Capabilities
```typescript
import { getDatabaseCapabilities } from './db/index.js';

const capabilities = await getDatabaseCapabilities('hybrid');
console.log('Supported operations:', capabilities.supportedOperations);
```

## Performance Improvements

### 1. Connection Pooling
- Separate connection pools for each adapter
- Configurable pool sizes and timeouts
- Health monitoring and automatic recovery

### 2. Batch Operations
- Improved batch processing for large datasets
- Parallel processing where possible
- Memory-efficient streaming for large results

### 3. Caching
- Built-in caching for frequently accessed data
- Configurable cache TTL and size limits
- Cache invalidation strategies

## Error Handling

### New Error Types
```typescript
// Factory errors
DatabaseFactoryError
ConfigurationError
AdapterCreationError
UnsupportedDatabaseError

// Database errors
DatabaseError
ConnectionError
ValidationError
NotFoundError
DuplicateError
```

### Error Recovery
- Automatic retry with exponential backoff
- Graceful degradation when adapters fail
- Circuit breaker pattern for fault tolerance

## Monitoring and Observability

### Health Checks
```typescript
// Health monitoring
await db.healthCheck();

// Detailed health report
const health = await db.getMetrics();
console.log('Connection status:', health.healthy);
console.log('Query latency:', health.queryLatency);
```

### Performance Metrics
```typescript
// Get performance statistics
const stats = await db.getStatistics();
console.log('Total items:', stats.totalItems);
console.log('Items by kind:', stats.itemsByKind);
console.log('Storage size:', stats.storageSize);
```

## Backward Compatibility

The new architecture maintains full backward compatibility:

- Existing `UnifiedDatabaseLayer` API unchanged
- All existing method signatures preserved
- Legacy exports available (deprecated)
- Gradual migration path supported

## Best Practices

### 1. Configuration Management
- Use environment variables for sensitive data
- Validate configuration at startup
- Use the factory pattern for adapter creation

### 2. Error Handling
- Always wrap database operations in try-catch
- Use specific error types for proper handling
- Implement retry logic for transient failures

### 3. Performance
- Use appropriate batch sizes for bulk operations
- Monitor connection pool usage
- Implement caching for frequently accessed data

### 4. Testing
- Test with real database connections
- Mock adapters for unit tests
- Test error scenarios and recovery

## Troubleshooting

### Common Issues

1. **Connection Errors**
   - Check environment variables
   - Verify database is running
   - Check network connectivity

2. **Type Errors**
   - Ensure proper imports
   - Check interface implementations
   - Use proper TypeScript configuration

3. **Performance Issues**
   - Monitor connection pool usage
   - Check query performance with EXPLAIN
   - Consider caching strategies

### Debug Mode

Enable debug logging:
```typescript
const db = createUnifiedDatabaseLayer({
  type: 'hybrid',
  postgres: { logQueries: true },
  qdrant: { logQueries: true }
});
```

## Future Enhancements

1. **Multi-database Support**: Extend factory for other database types
2. **Advanced Caching**: Redis integration for distributed caching
3. **Query Optimization**: Automatic query optimization suggestions
4. **Migration Tools**: Automated schema migration utilities
5. **Observability**: Enhanced metrics and tracing integration

## Conclusion

This refactoring provides a solid foundation for future development while maintaining backward compatibility. The new architecture is:

- **Maintainable**: Clear separation of concerns and single responsibilities
- **Testable**: Modular design with dependency injection
- **Scalable**: Factory pattern for easy extension
- **Type-safe**: Full TypeScript support with proper interfaces
- **Performant**: Optimized connection handling and batch operations

The migration path is designed to be gradual, allowing existing code to continue working while adopting new patterns incrementally.