# Cortex Memory MCP Architecture

## Overview

Cortex Memory MCP Server implements a **Qdrant-only architecture** that provides vector-based storage and semantic search capabilities. The system uses Qdrant as the sole database for all operations, eliminating complexity and ensuring consistent performance.

⚠️ **IMPORTANT NOTICE**: This system uses **QDRANT ONLY**. PostgreSQL is NOT used and should NOT be configured or installed.

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
│                 Qdrant Database Layer                       │
│                                                             │
│              ┌─────────────────────────────┐               │
│              │        QDRANT VECTOR DB      │               │
│              │   • Semantic Search         │               │
│              │   • Vector Storage          │               │
│              │   • Metadata Storage        │               │
│              │   • Similarity Search       │               │
│              └─────────────────────────────┘               │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Qdrant Database Layer

The `QdrantAdapter` class provides a single interface for all database operations using Qdrant as the sole storage backend.

**Key Features**:
- Single interface for vector-based storage
- Semantic search and similarity matching
- Type-safe TypeScript operations
- Comprehensive error handling
- Automatic embedding generation and storage
- Metadata filtering and retrieval

**Qdrant Capabilities**:
- Vector similarity search
- Semantic understanding
- Embedding storage and retrieval
- Metadata filtering with JSON payloads
- Collection management
- Approximate nearest neighbor search
- Real-time indexing and search

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
Implements basic semantic search:

```
Memory Find Service
├── Query Parser (Basic query processing)
├── Search Service (Semantic vector search only)
└── Context Generator (Basic search context)
```

**⚠️ Current Limitations:**
- No strategy selector (only semantic search available)
- No result ranker (basic similarity scoring only)
- No autonomous context creation (basic metadata only)
- No natural language processing capabilities

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

### Storage Flow (Current Implementation)

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
│ - Basic type checking                      │
│ - Schema validation                        │
└─────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────┐
│ Deduplication Service                      │
│ - Content similarity detection (85%)       │
│ - Basic duplicate identification            │
│ - Skip storage if duplicate                 │
└─────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────┐
│ Qdrant Database Layer                      │
│ - Vector storage and retrieval             │
│ - Semantic search capabilities             │
│ - Metadata filtering and storage           │
│ - Automatic embedding generation           │
└─────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────┐
│ Auto-Purge Service                         │
│ - TTL-based cleanup                        │
│ - 90-day purge for most types              │
│ - 30-day purge for PR context              │
└─────────────────────────────────────────────┘
    ↓
Response with Basic Context
```

**⚠️ Missing Components:**
- No conflict resolution in deduplication
- No relationship detection in similarity service
- No comprehensive audit service
- No autonomous context generation

### Search Flow (Current Implementation)

```
Search Query
    ↓
Memory Find Service
    ↓
┌─────────────────────────────────────────────┐
│ Query Parser                               │
│ - Basic query processing                    │
│ - Text normalization                       │
└─────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────┐
│ Search Execution                           │
│ - Semantic search (Qdrant vectors only)   │
│ - Vector similarity matching               │
│ - Metadata filtering                       │
└─────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────┐
│ Result Processing                          │
│ - Basic similarity scoring                 │
│ - Result ranking                           │
│ - Deduplication                            │
└─────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────┐
│ Context Generation                         │
│ - Search mode used                        │
│ - Result count                            │
│ - Basic metadata                          │
└─────────────────────────────────────────────┘
    ↓
Results with Basic Context
```

**⚠️ Missing Components:**
- No user suggestions or recommendations
- No advanced search analytics
- No autonomous context generation

## Search Strategies

### 1. Semantic Search (Primary)
Vector-based similarity search using Qdrant:

```typescript
// Implementation flow
const embedding = await openai.createEmbedding(query);
const results = await qdrant.similaritySearch(embedding);
```

### 2. Metadata Filtered Search
Vector search with metadata filtering:

```typescript
// Vector search with metadata filters
const results = await qdrant.search({
  vector: embedding,
  filter: {
    must: [
      { key: "kind", match: { value: "entity" }},
      { key: "scope.project", match: { value: "project-name" }}
    ]
  }
});
```

### 3. Hybrid Semantic Search
Multi-factor semantic search with weighting:

```typescript
// Weighted semantic search
const results = await qdrant.search({
  vector: embedding,
  payload: {
    title: item.title,
    content: item.content,
    kind: item.kind
  }
});
```

### 4. Fallback Search
Basic text matching in metadata:

```typescript
// Text matching in stored metadata
const results = await qdrant.search({
  query: "text search in metadata",
  search_type: "text"
});
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
      qdrant: {
        url: process.env.QDRANT_URL || 'http://localhost:6333',
        apiKey: process.env.QDRANT_API_KEY,
        vectorSize: parseInt(process.env.VECTOR_SIZE || '1536'),
        timeout: parseInt(process.env.QDRANT_TIMEOUT || '5000'),
        maxRetries: parseInt(process.env.QDRANT_MAX_RETRIES || '3')
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

### 1. Connection Management

```typescript
// Qdrant client connection
const qdrantClient = new QdrantClient({
  url: config.qdrantUrl,
  apiKey: config.qdrantApiKey,
  timeout: config.connectionTimeout,
  maxRetries: config.maxRetries
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
// Qdrant search optimization
const optimizedSearch = await qdrantClient.search({
  collection_name: 'knowledge_entities',
  query_vector: embedding,
  query_filter: {
    must: [
      { key: "entity_type", match: { value: entityType } },
      { key: "created_at", range: { gt: timestamp } }
    ]
  },
  limit: 50,
  score_threshold: 0.7
});
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

- **Qdrant**: Distributed cluster for vector search with sharding
- **Application**: Stateless services with load balancing
- **OpenAI API**: Multiple API keys for rate limit handling

### 2. Data Partitioning

```typescript
// Qdrant sharding and partitioning
const collectionConfig = {
  shard_number: 4,  // Number of shards
  replication_factor: 2,  // Replicas per shard
  write_consistency_factor: 2,
  on_disk_payload: true,  // Store payloads on disk
  hnsw_config: {
    m: 16,  // HNSW connectivity
    ef_construct: 100,  // Index construction accuracy
    full_scan_threshold: 10000
  }
};

// Collections can be organized by project or scope
const projectCollection = `cortex-memory-${projectScope}`;
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

## Current Implementation vs Target Architecture

### ✅ **What Exists Today (Current v1.0)**

**Core Functionality:**
- Qdrant vector database with semantic search
- Basic MCP protocol implementation
- 4 fully implemented knowledge types (section, decision, todo, issue)
- Basic deduplication (85% similarity threshold)
- TTL-based auto-purge system
- Comprehensive schema validation for 16 types

**Service Layer:**
- Memory Store Service with validation and deduplication
- Memory Find Service with basic semantic search
- Auto-Purge Service for maintenance operations
- Basic error handling and logging

### 🚧 **What's Missing (Target Features)**

**Advanced Search:**
- Multi-strategy search (semantic + keyword + hybrid)
- Search mode selection (auto/fast/deep)
- Confidence scoring and result ranking
- Query expansion and suggestions

**AI-Enhanced Features:**
- Autonomous context generation
- Natural language processing and intent analysis
- Contradiction detection and merge suggestions
- Smart recommendations and user insights

**Graph Functionality:**
- Entity relationship mapping
- Graph traversal algorithms
- Relationship-based search and discovery

**Content Management:**
- Document chunking and parent-child relationships
- Large document handling (8k+ character content)
- Content organization and hierarchical structures

### 🚨 **Critical Architecture Issues**

**Disconnected Implementation:**
- Main server bypasses comprehensive service layer
- Memory find has circular dependency on memory store
- Advanced features exist in services but aren't accessible
- Architecture documentation doesn't match actual implementation

**Missing Knowledge Type Logic:**
- 6 knowledge types are placeholders only (runbook, change, etc.)
- 6 types have only basic storage without business rules
- Only 4 types have complete validation and business logic

### 📋 **Implementation Priority**

1. **Critical (P1)**: Fix service layer integration and circular dependencies
2. **High (P2)**: Complete missing knowledge type implementations
3. **Medium (P3)**: Add graph functionality and advanced search
4. **Low (P4)**: Implement AI-enhanced features and content management

## Summary

The Cortex Memory MCP system has a solid foundation with Qdrant-based vector storage and basic semantic search. However, there are significant gaps between the documented architecture and actual implementation. The primary issues are:

1. **Service Layer Disconnect**: Comprehensive services exist but main server bypasses them
2. **Missing Feature Logic**: Many knowledge types are placeholders without implementation
3. **Aspirational Documentation**: Advanced features described but not built

This architecture documentation has been updated to reflect the current reality while preserving the target vision for future development.

This architecture provides a robust, scalable foundation for knowledge management that can handle both structured data and semantic search requirements effectively.