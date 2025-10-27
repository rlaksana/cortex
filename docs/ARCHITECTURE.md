# Cortex Memory MCP Architecture

## Overview

Cortex Memory MCP Server implements a sophisticated dual-database architecture that combines PostgreSQL's relational capabilities with Qdrant's vector search functionality. This unified approach provides both structured data management and semantic search capabilities in a single, cohesive system.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MCP Protocol Layer                        │
├─────────────────────────────────────────────────────────────┤
│                    Service Layer                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐│
│  │ Memory Store    │  │ Memory Find     │  │ Orchestrators   ││
│  │ Service         │  │ Service         │  │                 ││
│  └─────────────────┘  └─────────────────┘  └─────────────────┘│
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐│
│  │ Similarity      │  │ Deduplication   │  │ Validation      ││
│  │ Service         │  │ Service         │  │ Service         ││
│  └─────────────────┘  └─────────────────┘  └─────────────────┘│
├─────────────────────────────────────────────────────────────┤
│                Unified Database Layer                       │
│  ┌─────────────────┐              ┌─────────────────┐      │
│  │   PostgreSQL    │ ◄────────────►│     Qdrant      │      │
│  │   Relational    │   Unified     │   Vector DB     │      │
│  │   Data + FTS    │   Interface    │   Semantic      │      │
│  └─────────────────┘              └─────────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Unified Database Layer

The `UnifiedDatabaseLayer` class provides a single interface for all database operations, coordinating between PostgreSQL and Qdrant.

**Key Features**:
- Single interface for multiple database types
- Connection pooling and performance optimization
- Type-safe TypeScript operations
- Comprehensive error handling
- Graceful degradation and fallbacks

**PostgreSQL Responsibilities**:
- Structured relational data storage
- Full-text search with PostgreSQL's `tsvector`
- Complex queries and aggregations
- ACID transactions
- JSON/JSONB operations
- Array operations and indexing

**Qdrant Responsibilities**:
- Vector similarity search
- Semantic understanding
- Embedding storage and retrieval
- Approximate nearest neighbor search
- Collection management

### 2. Service Layer Architecture

#### Memory Store Service
Coordinates the storage of knowledge items through multiple specialized services:

```
Memory Store Service
├── Validation Service (Input validation & business rules)
├── Deduplication Service (Duplicate detection & handling)
├── Similarity Service (Content similarity analysis)
├── Audit Service (Comprehensive audit logging)
└── Storage Orchestrator (Coordinates all services)
```

#### Memory Find Service
Implements intelligent search with multiple strategies:

```
Memory Find Service
├── Query Parser (Natural language processing)
├── Strategy Selector (Automatic strategy selection)
├── Search Service (Multi-strategy execution)
├── Result Ranker (Relevance scoring)
└── Context Generator (Autonomous context creation)
```

### 3. Knowledge Type System

The system supports 16 comprehensive knowledge types, each with specific handling:

**Core Types**:
- `entity`: Graph nodes representing concepts or objects
- `relation`: Graph edges connecting entities
- `observation`: Fine-grained data attached to entities

**Documentation Types**:
- `section`: Document containers
- `runbook`: Step-by-step procedures
- `decision`: Architecture Decision Records (ADRs)

**Tracking Types**:
- `todo`: Tasks and action items
- `issue`: Bug tracking and problems
- `change`: Code change tracking
- `release`: Release deployment tracking
- `incident`: Incident response management
- `risk`: Risk assessment
- `assumption`: Business/technical assumptions

**Metadata Types**:
- `ddl`: Database schema changes
- `pr_context`: Pull request metadata
- `release_note`: Release documentation

## Data Flow Architecture

### Storage Flow

```
User Request
    ↓
MCP Protocol Layer
    ↓
Memory Store Service
    ↓
┌─────────────────────────────────────────────┐
│ Validation Service                         │
│ - Input validation                         │
│ - Business rule enforcement                │
│ - Type checking                            │
└─────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────┐
│ Deduplication Service                      │
│ - Semantic similarity detection            │
│ - Duplicate identification                 │
│ - Conflict resolution                      │
└─────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────┐
│ Similarity Service                         │
│ - Content analysis                         │
│ - Similarity scoring                       │
│ - Relationship detection                   │
└─────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────┐
│ Unified Database Layer                     │
│ - PostgreSQL storage (structured data)     │
│ - Qdrant storage (vectors & search)        │
│ - Transaction coordination                 │
└─────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────┐
│ Audit Service                              │
│ - Operation logging                        │
│ - Change tracking                          │
│ - Compliance reporting                     │
└─────────────────────────────────────────────┘
    ↓
Response with Autonomous Context
```

### Search Flow

```
Search Query
    ↓
Memory Find Service
    ↓
┌─────────────────────────────────────────────┐
│ Query Parser                               │
│ - Natural language processing               │
│ - Intent analysis                          │
│ - Query decomposition                      │
└─────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────┐
│ Strategy Selector                          │
│ - Query complexity analysis                 │
│ - Performance requirements                  │
│ - Available data types                     │
└─────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────┐
│ Search Execution                           │
│ - Semantic search (Qdrant)                 │
│ - Full-text search (PostgreSQL)            │
│ - Hybrid search (both)                     │
│ - Fallback search                           │
└─────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────┐
│ Result Processing                          │
│ - Relevance scoring                        │
│ - Result ranking                           │
│ - Deduplication                            │
└─────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────┐
│ Context Generation                         │
│ - Search strategy used                     │
│ - Result statistics                        │
│ - User suggestions                         │
└─────────────────────────────────────────────┘
    ↓
Ranked Results with Autonomous Context
```

## Search Strategies

### 1. Hybrid Search (Default)
Combines semantic and keyword search for comprehensive results:

```typescript
// Implementation flow
const semanticResults = await qdrant.search(query);
const keywordResults = await postgresql.fullTextSearch(query);
const hybridResults = mergeAndRank(semanticResults, keywordResults);
```

### 2. Semantic Search
Pure vector similarity using Qdrant:

```typescript
// Vector embeddings + similarity search
const embedding = await openai.createEmbedding(query);
const results = await qdrant.similaritySearch(embedding);
```

### 3. Full-Text Search
PostgreSQL's advanced text search capabilities:

```typescript
// tsvector + tsquery search
const results = await postgresql.fullTextSearch({
  query,
  weighting: { D: 0.1, C: 0.2, B: 0.4, A: 0.8 },
  normalization: 32,
  highlight: true
});
```

### 4. Fallback Search
Basic pattern matching when other methods fail:

```typescript
// ILIKE pattern matching
const results = await postgresql.fallbackSearch(query);
```

## Similarity Service Architecture

The similarity service provides sophisticated content analysis:

### Multi-Factor Similarity

```typescript
interface SimilarityFactors {
  content: number;    // Jaccard similarity on content
  title: number;      // Levenshtein distance on titles
  kind: number;       // Type matching (exact or partial)
  scope: number;      // Project/branch/org similarity
  overall: number;    // Weighted combination
}
```

### Weighting Configuration

```typescript
interface WeightingConfig {
  content: 0.5;    // Primary factor
  title: 0.2;      // Secondary factor
  kind: 0.1;       // Type importance
  scope: 0.2;      // Context relevance
}
```

## Error Handling Architecture

### Graceful Degradation

The system implements multi-level fallbacks:

```
Primary Strategy
    ↓ (fails)
Secondary Strategy
    ↓ (fails)
Tertiary Strategy
    ↓ (fails)
Graceful Degradation
```

### Error Recovery

```typescript
// Example: Database connection error handling
try {
  await primaryDatabaseOperation();
} catch (error) {
  await fallbackWithTimeout();
  if (stillFails) {
    await cachedResponse();
    if (noCache) {
      return gracefulDegradationResponse();
    }
  }
}
```

## Configuration System

### Environment-Based Configuration

```typescript
class Environment {
  private static instance: Environment;

  getDatabaseConfig(): DatabaseConfig {
    return {
      postgres: {
        url: process.env.DATABASE_URL,
        poolSize: parseInt(process.env.DB_POOL_SIZE || '10'),
        timeout: parseInt(process.env.DB_TIMEOUT || '30000')
      },
      qdrant: {
        url: process.env.QDRANT_URL || 'http://localhost:6333',
        apiKey: process.env.QDRANT_API_KEY,
        vectorSize: parseInt(process.env.VECTOR_SIZE || '1536')
      }
    };
  }

  getSearchConfig(): SearchConfig {
    return {
      defaultLimit: parseInt(process.env.SEARCH_LIMIT || '50'),
      similarityThreshold: parseFloat(process.env.SIMILARITY_THRESHOLD || '0.7'),
      enableCaching: process.env.ENABLE_CACHE === 'true'
    };
  }
}
```

## Performance Optimizations

### 1. Connection Pooling

```typescript
// PostgreSQL connection pool
const postgresPool = new Pool({
  connectionString: config.postgresUrl,
  max: config.maxConnections,
  connectionTimeoutMillis: config.connectionTimeout,
  idleTimeoutMillis: config.idleTimeout
});

// Qdrant connection management
const qdrantClient = new QdrantClient({
  url: config.qdrantUrl,
  timeout: config.connectionTimeout,
  maxRetries: config.maxRetries
});
```

### 2. Query Optimization

```typescript
// PostgreSQL query optimization
const optimizedQuery = `
  SELECT * FROM knowledge_entities
  WHERE
    entity_type = $1
    AND created_at > $2
    AND search_vector @@ websearch_to_tsquery($3)
  ORDER BY ts_rank_cd(search_vector, websearch_to_tsquery($3)) DESC
  LIMIT $4
`;
```

### 3. Caching Strategy

```typescript
interface CacheConfig {
  searchResults: {
    ttl: 3600;      // 1 hour
    maxSize: 1000;  // Max cached results
  };
  embeddings: {
    ttl: 86400;     // 24 hours
    maxSize: 10000; // Max cached embeddings
  };
}
```

## Security Architecture

### 1. Authentication

```typescript
interface AuthConfig {
  apiKeyValidation: boolean;
  jwtValidation: boolean;
  sessionManagement: boolean;
  rateLimiting: {
    requestsPerMinute: number;
    burstLimit: number;
  };
}
```

### 2. Authorization

```typescript
interface ScopePermissions {
  project: string;    // Project-level access
  branch?: string;    // Branch-level access
  org?: string;       // Organization-level access
  permissions: string[]; // ['read', 'write', 'delete']
}
```

### 3. Input Validation

```typescript
class ValidationService {
  validateKnowledgeItem(item: KnowledgeItem): ValidationResult {
    return {
      isValid: this.validateStructure(item) &&
               this.validateContent(item) &&
               this.validateScope(item),
      errors: this.collectValidationErrors(item)
    };
  }
}
```

## Monitoring and Observability

### 1. Health Checks

```typescript
interface HealthCheck {
  database: {
    postgres: boolean;
    qdrant: boolean;
  };
  services: {
    memoryStore: boolean;
    memoryFind: boolean;
    similarity: boolean;
  };
  performance: {
    responseTime: number;
    throughput: number;
    errorRate: number;
  };
}
```

### 2. Metrics Collection

```typescript
interface PerformanceMetrics {
  operations: {
    memoryStore: OperationMetrics;
    memoryFind: OperationMetrics;
  };
  database: {
    postgres: DatabaseMetrics;
    qdrant: DatabaseMetrics;
  };
  search: {
    strategyUsage: Record<string, number>;
    averageResponseTime: number;
    hitRate: number;
  };
}
```

### 3. Logging Strategy

```typescript
// Structured logging with correlation IDs
logger.info({
  operation: 'memory_store',
  correlationId: 'uuid',
  itemCount: items.length,
  duration: Date.now() - startTime,
  result: 'success'
});
```

## Scalability Considerations

### 1. Horizontal Scaling

- **PostgreSQL**: Read replicas for read-heavy workloads
- **Qdrant**: Distributed cluster for vector search
- **Application**: Stateless services with load balancing

### 2. Data Partitioning

```typescript
// PostgreSQL partitioning by date
CREATE TABLE knowledge_entities_2025_01 PARTITION OF knowledge_entities
FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

// Qdrant sharding by project
const collectionConfig = {
  shard_number: 4,  // Number of shards
  replication_factor: 2,  // Replicas per shard
  write_consistency_factor: 2
};
```

### 3. Caching Layers

```typescript
// Multi-level caching
interface CacheHierarchy {
  level1: 'in-memory';    // Application-level cache
  level2: 'redis';       // Distributed cache
  level3: 'database';    // Persistent storage
}
```

## Development and Deployment Architecture

### 1. Container Architecture

```dockerfile
# Multi-stage build
FROM node:20-alpine AS builder
# Build stage

FROM node:20-alpine AS runtime
# Runtime stage with minimal footprint
```

### 2. Environment Configurations

```typescript
enum Environment {
  DEVELOPMENT = 'development',
  STAGING = 'staging',
  PRODUCTION = 'production'
}

interface ConfigProfile {
  development: {
    logLevel: 'debug';
    database: 'local';
    cacheEnabled: false;
  };
  staging: {
    logLevel: 'info';
    database: 'staging-db';
    cacheEnabled: true;
  };
  production: {
    logLevel: 'warn';
    database: 'prod-cluster';
    cacheEnabled: true;
  };
}
```

## Migration Strategy

### 1. Database Migrations

```typescript
// PostgreSQL migrations
interface Migration {
  version: string;
  description: string;
  up: () => Promise<void>;
  down: () => Promise<void>;
}

// Qdrant collection migrations
interface CollectionMigration {
  collectionName: string;
  operation: 'create' | 'update' | 'delete';
  config: CollectionConfig;
}
```

### 2. Backward Compatibility

```typescript
// Version compatibility layer
interface CompatibilityLayer {
  supportVersion: string;
  deprecatedFeatures: string[];
  migrationPaths: Record<string, MigrationPath>;
}
```

This architecture provides a robust, scalable foundation for knowledge management that can handle both structured data and semantic search requirements effectively.