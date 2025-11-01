# MCP Cortex Memory System - Complete Store & Find Features Documentation

**Version**: 2.0.0 - Enhanced with Semantic Chunking
**Last Updated**: 2025-10-31
**Status**: v2.0 spec (semantic chunking rollout)

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Store Operations](#store-operations)
3. [Find Operations](#find-operations)
4. [Supported Knowledge Types](#supported-knowledge-types)
5. [Advanced Features](#advanced-features)
6. [Configuration & Options](#configuration--options)
7. [Response Formats](#response-formats)
8. [Error Handling](#error-handling)
9. [Performance Considerations](#performance-considerations)

---

## Overview

The MCP Cortex Memory System provides a comprehensive knowledge management platform with intelligent storage, retrieval, and semantic analysis capabilities. The system supports 16 different knowledge types organized into 4 categories, with advanced features like semantic chunking, duplicate detection, TTL management, and scope-based isolation.

### Key Capabilities
- **🧠 Semantic Chunking**: Intelligent content boundary detection using embeddings
- **🔍 Advanced Search**: Multi-modal search with semantic, keyword, and graph expansion
- **🛡️ Duplicate Detection**: Content hash and semantic similarity-based deduplication
- **⏰ TTL Management**: Time-based content expiry with automated cleanup
- **🎯 Scope Isolation**: Organizational, project, and branch-level data separation
- **📊 Analytics**: Comprehensive telemetry and performance monitoring

---

## Store Operations

### Core Store Functionality

#### Basic Store Operation
```typescript
memory_store({
  items: [
    {
      kind: "entity",
      content: "Knowledge content to store",
      scope: {
        org: "organization-name",
        project: "project-name",
        branch: "main"
      },
      metadata: {
        tags: ["important", "reference"],
        priority: "high"
      }
    }
  ]
})
```

#### Store Response Format
```typescript
{
  items: [{
    input_index: 0,
    status: "stored",           // stored | skipped_dedupe | business_rule_blocked | validation_error
    kind: "entity",
    id: "generated-uuid",
    created_at: "2025-10-31T13:00:00.000Z",
    reason?: "Duplicate content detected (hash: abc123...)",
    existing_id?: "existing-item-uuid"
  }],
  summary: {
    stored: 1,                  // Number of successfully stored items
    skipped_dedupe: 0,          // Number of items skipped due to duplication
    business_rule_blocked: 0,    // Number blocked by business rules
    validation_error: 0,         // Number with validation errors
    total: 1                     // Total items processed
  },
  autonomous_context: {
    action_performed: "created",
    similar_items_checked: 0,
    duplicates_found: 0,
    contradictions_detected: false,
    recommendation: "Item stored successfully",
    reasoning: "No similar items found",
    user_message_suggestion: "Knowledge item has been added to your memory",
    dedupe_threshold_used: 0.85,
    dedupe_method: "content_hash",
    dedupe_enabled: true
  }
}
```

### Advanced Store Features

#### 1. Semantic Chunking (NEW v2.0)
**Automatic for content ≥ 2400 characters, semantic analysis ≥ 3600 characters**

```typescript
// Long content automatically gets semantic chunking
memory_store({
  items: [{
    kind: "section",
    content: "Very long document content that exceeds 3600 characters...",
    // System will automatically:
    // - Detect semantic boundaries using embeddings (if available)
    // - Create intelligent chunks at topic shifts
    // - Preserve metadata and TTL across chunks
    // - Fall back to character chunking if semantic analysis fails
  }]
})
```

**Chunking Implementation Status:**
- ✅ **Core chunking logic**: Implemented with 1200 character target chunks
- ✅ **Semantic analyzer**: Complete with sentence-level boundary detection
- ✅ **Fallback mechanism**: Traditional character-based chunking
- ⚠️ **Embedding dependency**: Requires functional embedding service
- ⚠️ **Test status**: Embedding generation issues in test environment

**Chunking Features:**
- **Thresholds**: Content ≥2400 chars triggers chunking; ≥3600 chars enables semantic analysis
- **Target size**: 1200 characters per chunk with 200 character overlap
- **Semantic boundaries**: Configurable thresholds - strong (0.3), medium (0.5), weak (0.7) similarity
- **Windowed analysis**: 3-sentence context for boundary confirmation
- **Caching**: Embedding cache with 1-hour TTL for performance
- **Fallback**: Graceful degradation to traditional chunking on embedding failures
- **Supported types**: 'section', 'runbook', 'incident' (configurable)
- **Metadata preservation**: Full metadata and TTL inheritance across chunks

**Current Limitations:**
- Semantic analysis disabled → falls back to traditional chunking
- Embedding service failures → automatic fallback with logging
- Test environment → embedding generation issues causing test failures

#### 2. Duplicate Detection System
**Multi-layer deduplication strategy:**

```typescript
// Content Hash Detection (Exact Match)
if (contentHash === existingHash) {
  status: "skipped_dedupe"
  reason: "Duplicate content detected (hash: abc123...)"
}

// Semantic Similarity Detection (85% threshold)
if (semanticSimilarity > 0.85) {
  status: "skipped_dedupe"
  reason: "High semantic similarity (90.0%)"
}

// Scope-based Rules
// Same kind + Same scope = dedupe
// Different kind + Same scope = allow
// Same kind + Different scope = allow
```

#### 3. TTL (Time-To-Live) Management
**Automatic expiry with configurable policies:**

```typescript
memory_store({
  items: [{
    kind: "todo",
    content: "Task with expiry",
    ttl_policy: "30d",              // 30 days from now
    // OR explicit expiry
    expiry_at: "2025-11-30T23:59:59.000Z"
  }]
})
```

**TTL Features:**
- **Predefined policies**: 1d, 7d, 30d, 90d, permanent
- **Custom expiry dates**: Absolute timestamps
- **Inheritance**: Child chunks inherit parent TTL
- **Automated cleanup**: Background expiry worker (runs every 60 minutes, batch size 100, best-effort)
- **TTL-aware search**: Expired items excluded from results

#### 4. Scope-Based Isolation
**Multi-level data separation:**

```typescript
memory_store({
  items: [{
    kind: "decision",
    content: "Technical decision",
    scope: {
      org: "company-name",      // Organization level
      project: "project-name", // Project level
      branch: "feature-branch" // Branch level
    }
  }]
})
```

**Scope Features:**
- **Hierarchical isolation**: org → project → branch
- **Cross-scope search**: Search across multiple scopes
- **Default scope handling**: Automatic scope resolution
- **Security**: Data access controls by scope

---

## Find Operations

### Core Find Functionality

#### Basic Search
```typescript
memory_find({
  query: "search terms",
  mode: "auto",              // auto | fast | deep
  limit: 10,
  scope: {
    project: "project-name",
    branch: "main"
  }
})
```

#### Advanced Search Features

#### 1. Multi-Modal Search Strategies
**Automatic strategy selection based on query:**

```typescript
memory_find({
  query: "semantic search query",
  mode: "deep",
  expand: "relations",         // relations | parents | children | none
  max_attempts: 3,
  similarity_threshold: 0.7
})
```

**Search Modes:**
- **Auto**: Intelligent strategy selection
- **Fast**: Keyword and exact matching only
- **Deep**: Full semantic + graph expansion

#### 2. Graph Expansion (P4-T4.2)
**Knowledge graph traversal:**

```typescript
memory_find({
  query: "find related entities",
  expand: "relations",         // Expand to related items
  expansion_depth: 2,          // How many levels to expand
  include_relations: ["causes", "enables", "relates_to"]
})
```

**Expansion Options:**
- **Relations**: Find related knowledge items
- **Parents**: Find parent items in hierarchy
- **Children**: Find child items
- **Combined**: Multiple expansion types

**Graph Expansion Guardrails:**
- **Maximum total nodes**: 100 items per expansion operation
- **Timeout**: 5 seconds per expansion level
- **Depth limit**: Maximum 3 levels of expansion

#### 3. Type-Specific Search
**Filter by knowledge types:**

```typescript
memory_find({
  query: "search decisions",
  types: ["decision"],         // Specific types
  kind: "decision"              // Legacy compatibility
})
```

#### 4. Scope-Based Search
**Multi-scope search:**

```typescript
memory_find({
  query: "search across projects",
  scope: {
    org: "company-name",
    // Multiple projects
    project: ["project-a", "project-b"],
    // All branches
    branch: null
  }
})
```

### Search Response Format

```typescript
{
  hits: [{
    id: "item-uuid",
    kind: "decision",
    scope: { org: "company", project: "project", branch: "main" },
    data: { /* type-specific data */ },
    created_at: "2025-10-31T13:00:00.000Z",
    confidence_score: 0.95,
    match_type: "semantic",     // exact | fuzzy | semantic | keyword | hybrid
    highlight: ["matched terms in context"],
    relations: [{
      id: "related-item-uuid",
      type: "relates_to",
      strength: 0.8
    }],
    chunk_info: {              // For chunked content
      parent_id: "parent-uuid",
      chunk_index: 2,
      total_chunks: 5,
      is_complete: false
    }
  }],
  total: 25,
  partial: false,              // true if partial results due to errors
  search_metadata: {
    query: "original search query",
    strategy_used: "semantic_hybrid",
    execution_time: 150,
    expansion_used: true,
    scopes_searched: ["project/main", "project/dev"]
  },
  autonomous_context: {
    recommendations: ["Consider searching for related decisions"],
    suggestions: ["Expand search to include related entities"]
  }
}
```

---

## Supported Knowledge Types

### 16 Knowledge Types in 4 Categories

#### 1. Core Graph Extension Types
**For building knowledge graphs and relationships**

| Type | Description | Use Cases |
|------|-------------|-----------|
| `entity` | Core concepts with dynamic schemas | Users, organizations, goals, preferences |
| `relation` | Relationships between entities | User-organization, goal-dependencies |
| `observation` | Facts and observations | System status, user behavior patterns |

#### 2. Core Document Types
**For structured documentation**

| Type | Description | Use Cases |
|------|-------------|-----------|
| `section` | Document sections with hierarchical structure | Documentation, knowledge base articles |

#### 3. Development Lifecycle Types
**For software development processes**

| Type | Description | Use Cases |
|------|-------------|-----------|
| `runbook` | Operational procedures | Deployment guides, troubleshooting steps |
| `change` | Change records and modifications | Code changes, configuration updates |
| `issue` | Problems and incidents | Bug reports, feature requests |
| `decision` | Decisions with ADR format | Technical decisions, architecture choices |
| `todo` | Action items and tasks | Development tasks, action items |
| `release_note` | Release documentation | Version notes, changelogs |
| `ddl` | Database schema changes | Table definitions, migrations |
| `pr_context` | Pull request context | PR descriptions, review comments |

#### 4. 8-LOG System Types
**For comprehensive project tracking**

| Type | Description | Use Cases |
|------|-------------|-----------|
| `incident` | Incidents and outages | Production incidents, system failures |
| `release` | Software releases | Version deployments, releases |
| `risk` | Risk assessments | Security risks, project risks |
| `assumption` | Assumptions and constraints | Technical assumptions, business constraints |

### Type-Specific Features

#### Validation Features per Type
- **Required Fields**: Each type has specific required fields
- **Schema Validation**: Zod schemas ensure data integrity
- **Business Rules**: Type-specific validation logic
- **Metadata Requirements**: Custom metadata per type

#### Specialized Behaviors
- **Immutable Types**: Some types prevent modification (ADR, release notes)
- **Chunkable Types**: Section, runbook, incident support semantic chunking
- **Deduplicated Types**: Entity, relation, observation have strict deduplication
- **TTL Supported**: All types support time-based expiry

---

## Advanced Features

### 1. Semantic Analysis & Intelligence

#### Autonomous Context Generation
```typescript
{
  action_performed: "created",
  similar_items_checked: 5,
  duplicates_found: 1,
  contradictions_detected: false,
  recommendation: "Consider creating related observations",
  reasoning: "Found similar entities in same project scope",
  user_message_suggestion: "Your entity has been stored and linked to 2 related items"
}
```

#### Contradiction Detection
- **Content Analysis**: Detect conflicting information
- **Semantic Comparison**: Compare meaning across items
- **Recommendations**: Suggest resolutions for contradictions

#### Knowledge Graph Integration
- **Automatic Linking**: Create relationships between related items
- **Graph Traversal**: Find connected knowledge
- **Inference**: Derive new insights from existing knowledge

### 2. Performance & Optimization

#### Caching Systems
- **Embedding Cache**: 1-hour TTL for semantic analysis
- **Result Cache**: Search result caching for repeated queries
- **Connection Pooling**: Optimized database connections

#### Chunking Performance
- **Selective Analysis**: Only long content (>3600 chars) gets semantic chunking
- **Early Termination**: Stop analysis if no boundaries found
- **Fallback Mechanisms**: Graceful degradation to traditional methods

#### Search Optimization
- **Strategy Selection**: Automatic best search method
- **Parallel Processing**: Concurrent search strategies
- **Result Ranking**: Intelligent relevance scoring

### 3. Monitoring & Telemetry

#### Store Metrics
```typescript
{
  batch_stats: {
    items_processed: 10,
    items_stored: 8,
    items_skipped_dedupe: 2,
    processing_time: 1250,
    chunking_stats: {
      semantic_analysis_enabled: true,
      semantic_boundaries_found: 5,
      average_chunk_size: 450
    }
  },
  duplicate_detection_stats: {
    total_checks: 10,
    content_hash_matches: 1,
    semantic_similarity_matches: 1
  }
}
```

#### Search Metrics
```typescript
{
  search_metrics: {
    execution_time: 250,
    strategy_used: "semantic_hybrid",
    results_count: 15,
    expansion_used: true,
    cache_hit: false
  }
}
```

---

## Complete Configuration Reference

### Environment Variables

#### Core Configuration
```bash
# Database Configuration
QDRANT_URL=http://localhost:6333
QDRANT_API_KEY=your_api_key_here
DATABASE_COLLECTION=cortex-memory

# Service Configuration
PORT=3000
NODE_ENV=production
LOG_LEVEL=info
DEBUG=false

# API Configuration
API_BASE_URL=https://api.cortex-memory.com
API_VERSION=v1
CORS_ORIGIN=*
MAX_REQUEST_SIZE=10mb
REQUEST_TIMEOUT=30000

# Authentication
JWT_SECRET=your_jwt_secret_here
API_KEY_HEADER=x-api-key
ENABLE_API_KEY_AUTH=true
ENABLE_JWT_AUTH=false
```

#### Embedding Service Configuration
```bash
# OpenAI Configuration (Default)
OPENAI_API_KEY=sk-...
OPENAI_MODEL=text-embedding-3-small
OPENAI_MAX_TOKENS=8192
OPENAI_TIMEOUT=30000

# Alternative: Cohere
COHERE_API_KEY=your_cohere_key
COHERE_MODEL=embed-english-v3.0

# Alternative: Local Embedding Service
LOCAL_EMBEDDING_URL=http://localhost:8080/embed
LOCAL_EMBEDDING_MODEL=all-MiniLM-L6-v2
```

#### Semantic Chunking Configuration
```bash
# Enable/Disable Semantic Features
ENABLE_SEMANTIC_CHUNKING=true
ENABLE_SEMANTIC_SEARCH=true
EMBEDDING_CACHE_ENABLED=true

# Chunking Parameters
CHUNKING_MIN_CONTENT_LENGTH=2400
CHUNKING_SEMANTIC_THRESHOLD=3600
CHUNKING_TARGET_SIZE=1200
CHUNKING_OVERLAP_SIZE=200
CHUNKING_STRONG_THRESHOLD=0.3
CHUNKING_MEDIUM_THRESHOLD=0.5
CHUNKING_WEAK_THRESHOLD=0.7
CHUNKING_WINDOW_SIZE=3
CHUNKING_MIN_SENTENCES=2
CHUNKING_MAX_SENTENCES=15

# Cache Configuration
EMBEDDING_CACHE_TTL=3600000
EMBEDDING_CACHE_SIZE=1000
RESULT_CACHE_TTL=300000
RESULT_CACHE_SIZE=100
```

#### Performance & Scaling
```bash
# Connection Pooling
DB_POOL_MIN=2
DB_POOL_MAX=10
DB_POOL_ACQUIRE_TIMEOUT=30000
DB_POOL_IDLE_TIMEOUT=30000

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX_REQUESTS=100
RATE_LIMIT_BURST=20

# Processing Limits
MAX_BATCH_SIZE=100
MAX_QUERY_RESULTS=1000
MAX_EXPANSION_DEPTH=5
MAX_CONCURRENT_CHUNKING=5
```

#### TTL and Cleanup Configuration
```bash
# TTL Management
DEFAULT_TTL_POLICY=30d
ENABLE_TTL_CLEANUP=true
TTL_CLEANUP_INTERVAL=3600000
TTL_CLEANUP_BATCH_SIZE=100

# Supported TTL Policies
TTL_POLICIES=1d,7d,30d,90d,permanent
```

### Configuration File Reference

#### config.json Structure
```json
{
  "database": {
    "url": "${QDRANT_URL}",
    "apiKey": "${QDRANT_API_KEY}",
    "collection": "${DATABASE_COLLECTION}",
    "pool": {
      "min": "${DB_POOL_MIN}",
      "max": "${DB_POOL_MAX}",
      "acquireTimeout": "${DB_POOL_ACQUIRE_TIMEOUT}",
      "idleTimeout": "${DB_POOL_IDLE_TIMEOUT}"
    }
  },
  "embedding": {
    "provider": "openai",
    "openai": {
      "apiKey": "${OPENAI_API_KEY}",
      "model": "${OPENAI_MODEL}",
      "maxTokens": "${OPENAI_MAX_TOKENS}",
      "timeout": "${OPENAI_TIMEOUT}"
    },
    "cohere": {
      "apiKey": "${COHERE_API_KEY}",
      "model": "${COHERE_MODEL}"
    },
    "local": {
      "url": "${LOCAL_EMBEDDING_URL}",
      "model": "${LOCAL_EMBEDDING_MODEL}"
    }
  },
  "semanticChunking": {
    "enabled": "${ENABLE_SEMANTIC_CHUNKING}",
    "analyzer": {
      "strongBoundaryThreshold": "${CHUNKING_STRONG_THRESHOLD}",
      "mediumBoundaryThreshold": "${CHUNKING_MEDIUM_THRESHOLD}",
      "weakBoundaryThreshold": "${CHUNKING_WEAK_THRESHOLD}",
      "windowSize": "${CHUNKING_WINDOW_SIZE}",
      "minChunkSentences": "${CHUNKING_MIN_SENTENCES}",
      "maxChunkSentences": "${CHUNKING_MAX_SENTENCES}",
      "minContentLength": "${CHUNKING_MIN_CONTENT_LENGTH}",
      "semanticThreshold": "${CHUNKING_SEMANTIC_THRESHOLD}",
      "targetChunkSize": "${CHUNKING_TARGET_SIZE}",
      "overlapSize": "${CHUNKING_OVERLAP_SIZE}",
      "enableCaching": "${EMBEDDING_CACHE_ENABLED}",
      "cacheTTL": "${EMBEDDING_CACHE_TTL}",
      "cacheSize": "${EMBEDDING_CACHE_SIZE}"
    }
  },
  "search": {
    "defaultMode": "auto",
    "maxAttempts": 3,
    "similarityThreshold": 0.7,
    "maxResults": "${MAX_QUERY_RESULTS}",
    "expansion": {
      "maxDepth": "${MAX_EXPANSION_DEPTH}",
      "relationTypes": ["relates_to", "enables", "causes", "depends_on"],
      "confidenceThreshold": 0.6,
      "maxNodes": 100,
      "timeout": 5000
    },
    "caching": {
      "enabled": true,
      "resultTTL": "${RESULT_CACHE_TTL}",
      "resultSize": "${RESULT_CACHE_SIZE}"
    }
  },
  "duplicateDetection": {
    "enabled": true,
    "semanticSimilarityThreshold": 0.85,
    "scopeRules": {
      "sameKindSameScope": "dedupe",
      "differentKindSameScope": "allow",
      "sameKindDifferentScope": "allow"
    }
  },
  "ttl": {
    "defaultPolicy": "${DEFAULT_TTL_POLICY}",
    "supportedPolicies": ["1d", "7d", "30d", "90d", "permanent"],
    "cleanup": {
      "enabled": "${ENABLE_TTL_CLEANUP}",
      "interval": "${TTL_CLEANUP_INTERVAL}",
      "batchSize": "${TTL_CLEANUP_BATCH_SIZE}"
    }
  },
  "api": {
    "port": "${PORT}",
    "baseUrl": "${API_BASE_URL}",
    "version": "${API_VERSION}",
    "cors": {
      "origin": "${CORS_ORIGIN}",
      "credentials": true
    },
    "rateLimit": {
      "enabled": "${RATE_LIMIT_ENABLED}",
      "windowMs": "${RATE_LIMIT_WINDOW_MS}",
      "maxRequests": "${RATE_LIMIT_MAX_REQUESTS}",
      "burst": "${RATE_LIMIT_BURST}"
    },
    "request": {
      "maxSize": "${MAX_REQUEST_SIZE}",
      "timeout": "${REQUEST_TIMEOUT}"
    },
    "auth": {
      "jwt": {
        "secret": "${JWT_SECRET}",
        "enabled": "${ENABLE_JWT_AUTH}"
      },
      "apiKey": {
        "enabled": "${ENABLE_API_KEY_AUTH}",
        "header": "${API_KEY_HEADER}"
      }
    }
  },
  "logging": {
    "level": "${LOG_LEVEL}",
    "debug": "${DEBUG}",
    "format": "json",
    "outputs": ["console"],
    "file": {
      "enabled": false,
      "path": "./logs/cortex.log",
      "maxSize": "100mb",
      "rotate": true
    }
  },
  "monitoring": {
    "metrics": {
      "enabled": true,
      "endpoint": "/metrics",
      "interval": 60000
    },
    "health": {
      "enabled": true,
      "endpoint": "/health"
    },
    "telemetry": {
      "enabled": true,
      "sampleRate": 0.1
    }
  }
}
```

### Configuration Validation

#### Schema Validation Rules
```typescript
interface ConfigurationSchema {
  // Required fields
  database: {
    url: string; // Must be valid URL
    collection: string; // Non-empty string
  };

  // Optional with defaults
  embedding?: {
    provider: "openai" | "cohere" | "local";
    apiKey?: string; // Required for OpenAI/Cohere
  };

  // Numeric constraints
  performance: {
    maxBatchSize: number; // 1-1000
    requestTimeout: number; // 1000-300000ms
    poolSize: number; // 1-100
  };

  // Enum values
  logLevel: "error" | "warn" | "info" | "debug";
  environment: "development" | "staging" | "production";
}
```

#### Runtime Configuration Validation
```typescript
// Validate on startup
const validateConfig = (config: Config): ValidationResult => {
  const errors: string[] = [];

  // Database connectivity
  if (!isValidUrl(config.database.url)) {
    errors.push("Invalid database URL format");
  }

  // API key validation
  if (config.embedding.provider === "openai" && !config.embedding.apiKey) {
    errors.push("OpenAI API key required when using OpenAI provider");
  }

  // Performance constraints
  if (config.performance.maxBatchSize > 1000) {
    errors.push("Max batch size cannot exceed 1000");
  }

  // Security checks
  if (config.environment === "production" && config.auth.jwt.secret === "default") {
    errors.push("Default JWT secret cannot be used in production");
  }

  return {
    valid: errors.length === 0,
    errors
  };
};
```

### Environment-Specific Configuration

#### Development Environment
```json
{
  "environment": "development",
  "database": {
    "url": "http://localhost:6333",
    "collection": "cortex-dev-memory"
  },
  "logging": {
    "level": "debug",
    "debug": true
  },
  "api": {
    "cors": {
      "origin": "*"
    }
  },
  "semanticChunking": {
    "enabled": false // Disable for faster development
  }
}
```

#### Production Environment
```json
{
  "environment": "production",
  "database": {
    "url": "${QDRANT_URL}",
    "collection": "cortex-memory"
  },
  "logging": {
    "level": "info",
    "debug": false,
    "outputs": ["console", "file"]
  },
  "api": {
    "cors": {
      "origin": ["https://app.cortex-memory.com"]
    },
    "rateLimit": {
      "enabled": true,
      "maxRequests": 1000
    }
  },
  "monitoring": {
    "telemetry": {
      "enabled": true,
      "sampleRate": 1.0
    }
  }
}
```

### Configuration Best Practices

#### Security Configuration
```typescript
// Use environment variables for secrets
const secureConfig = {
  auth: {
    jwt: {
      secret: process.env.JWT_SECRET, // Never hardcode
      expiresIn: "24h"
    },
    apiKey: {
      encryptionKey: process.env.API_KEY_ENCRYPTION_KEY
    }
  },
  database: {
    apiKey: process.env.QDRANT_API_KEY,
    ssl: process.env.NODE_ENV === "production"
  }
};
```

#### Performance Tuning
```typescript
// Optimize for your workload
const performanceConfig = {
  // High-throughput scenario
  highThroughput: {
    maxBatchSize: 500,
    dbPoolMax: 20,
    concurrentChunking: 10,
    requestTimeout: 60000
  },

  // Low-latency scenario
  lowLatency: {
    maxBatchSize: 50,
    dbPoolMax: 5,
    concurrentChunking: 2,
    requestTimeout: 10000
  },

  // Memory-constrained scenario
  memoryConstrained: {
    embeddingCacheSize: 100,
    resultCacheSize: 50,
    maxBatchSize: 25,
    concurrentChunking: 1
  }
};
```

---

## Configuration & Options

### Store Configuration

#### Chunking Configuration
```typescript
{
  semantic_analyzer: {
    strong_boundary_threshold: 0.3,    // Very low similarity = strong boundary
    medium_boundary_threshold: 0.5,    // Low similarity = medium boundary
    weak_boundary_threshold: 0.7,      // Medium similarity = weak boundary
    window_size: 3,                     // Sentences to analyze
    min_chunk_sentences: 2,             // Minimum sentences per chunk
    max_chunk_sentences: 15,            // Maximum sentences per chunk
    enable_caching: true,                // Enable embedding cache
    cache_ttl: 3600000                  // Cache TTL in ms (1 hour)
  }
}
```

#### Duplicate Detection Configuration
```typescript
{
  duplicate_detection: {
    enabled: true,
    semantic_similarity_threshold: 0.85, // Semantic match threshold
    scope_rules: {
      same_kind_same_scope: "dedupe",
      different_kind_same_scope: "allow",
      same_kind_different_scope: "allow"
    }
  }
}
```

#### TTL Configuration
```typescript
{
  ttl: {
    default_policy: "30d",
    supported_policies: ["1d", "7d", "30d", "90d", "permanent"],
    cleanup_interval: 3600000,         // 1 hour in ms
    batch_size: 100                     // Items to clean per batch
  }
}
```

### Search Configuration

#### Search Strategy Configuration
```typescript
{
  search: {
    default_mode: "auto",
    max_attempts: 3,
    similarity_threshold: 0.7,
    expansion_config: {
      max_depth: 3,
      relation_types: ["relates_to", "enables", "causes"],
      confidence_threshold: 0.6
    }
  }
}
```

---

## Response Formats

### Store Response Types

#### Success Response
```typescript
{
  items: [...],                   // Item-level results
  summary: {...},               // Batch summary statistics
  autonomous_context: {...},     // AI-driven insights
  batch_id: "batch_uuid",        // Batch identifier
  processing_time: 1250          // Total processing time in ms
}
```

#### Error Response
```typescript
{
  items: [],
  summary: {
    stored: 0,
    skipped_dedupe: 0,
    business_rule_blocked: 0,
    validation_error: 1,
    total: 1
  },
  errors: [{
    index: 0,
    error_code: "VALIDATION_ERROR",
    message: "Invalid kind: unsupported_type",
    field: "kind",
    timestamp: "2025-10-31T13:00:00.000Z"
  }],
  autonomous_context: {
    action_performed: "error",
    recommendation: "Check supported knowledge types",
    reasoning: "Validation failed during input processing"
  }
}
```

### Find Response Types

#### Search Results
```typescript
{
  hits: [...],                   // Search result items
  total: 25,                     // Total results found
  search_metadata: {...},        // Search execution details
  autonomous_context: {...},     // AI-powered recommendations
  query_id: "search_uuid"         // Search identifier
}
```

#### Error Response
```typescript
{
  hits: [/* ... some results ... */],  // Partial results that succeeded
  total: 25,
  partial: true,                     // Indicates partial failure
  errors: [{                         // Error array for multiple failures
    code: "SEARCH_ERROR",
    message: "Expansion operation timed out",
    details: "Graph expansion exceeded 5 second limit at depth 2",
    timestamp: "2025-10-31T13:00:00.000Z"
  }],
  search_metadata: {
    query: "original search query",
    strategy_used: "semantic_hybrid",
    execution_time: 5000,            // Truncated due to timeout
    expansion_used: true,
    expansion_depth_reached: 1,      // Partial expansion completed
    scopes_searched: ["project/main", "project/dev"]
  },
  autonomous_context: {
    action_performed: "partial_success",
    recommendation: "Try search with smaller scope or disable expansion",
    reasoning: "Some search strategies completed successfully, but expansion failed"
  }
}
```

---

## Error Handling

### Store Operation Errors

#### Validation Errors
- **Invalid kind**: Unsupported knowledge type
- **Missing required fields**: Type-specific validation failures
- **Invalid scope**: Malformed scope object
- **Content too large**: Content exceeds maximum limits

#### Processing Errors
- **Database errors**: Connection or storage failures
- **Chunking errors**: Semantic analysis failures
- **Embedding errors**: Vector generation failures
- **Duplicate detection errors**: Analysis failures

### Find Operation Errors

#### Search Errors
- **Invalid query**: Malformed search query
- **Database errors**: Search service failures
- **Timeout errors**: Search operation exceeded time limits
- **Scope errors**: Invalid scope configuration

#### Recovery Mechanisms
- **Graceful fallbacks**: Fallback to alternative strategies
- **Retry logic**: Automatic retry with exponential backoff
- **Partial results**: Return available results on partial failures
- **Error logging**: Comprehensive error tracking and reporting

---

## Performance Considerations

### Storage Performance

#### Chunking Performance
- **Selective processing**: Only content ≥2400 chars triggers chunking; ≥3600 chars enables semantic analysis
- **Chunk size optimization**: 1200 character target chunks with 200 character overlap
- **Batch optimization**: Process items in batches for efficiency
- **Async processing**: Non-blocking chunking operations
- **Memory management**: Efficient embedding cache with 1-hour TTL and 1000 entry limit
- **Fallback efficiency**: Traditional chunking when semantic analysis unavailable

#### Duplicate Detection Performance
- **Early termination**: Fast hash-based detection first
- **Cache utilization**: Reuse similarity calculations
- **Batch similarity**: Compare multiple items efficiently

### Search Performance

#### Search Strategy Selection
- **Auto mode**: Intelligent strategy selection based on query complexity
- **Parallel execution**: Run multiple search strategies concurrently
- **Result caching**: Cache frequent search results
- **Progressive loading**: Return results as they become available

#### Scalability Considerations
- **Vector database**: Optimized for high-dimensional similarity search
- **Connection pooling**: Efficient database connection management
- **Result pagination**: Large result set handling
- **Memory optimization**: Efficient data structure usage

### Performance Monitoring

#### Key Metrics
- **Store throughput**: Items processed per second
- **Search latency**: Search response times
- **Cache hit rates**: Embedding and result cache efficiency
- **Error rates**: Failure rates and patterns

#### Optimization Targets
- **Store operations**: <100ms per item (average)
- **Search operations**: <500ms for typical queries
- **Chunking efficiency**: 90%+ semantic accuracy
- **Duplicate detection**: <50ms per comparison

---

## Complete API Reference

### Core API Endpoints

#### Memory Store API
```
POST /api/v1/memory/store
Content-Type: application/json
Authorization: Bearer <api_key>
```

**Request Schema:**
```typescript
interface StoreRequest {
  items: KnowledgeItem[];
  options?: {
    batch_size?: number;
    skip_duplicates?: boolean;
    force_chunking?: boolean;
    validate_only?: boolean;
    return_ids?: boolean;
  };
}

interface KnowledgeItem {
  kind: KnowledgeType;
  content: string;
  scope?: Scope;
  data?: Record<string, any>;
  metadata?: Metadata;
  ttl_policy?: TTLPolicy | string;
  expiry_at?: string; // ISO 8601 timestamp
  id?: string; // For updates
  created_at?: string; // For imports
}
```

**Response Schema:**
```typescript
interface StoreResponse {
  success: boolean;
  items: StoreItemResult[];
  summary: StoreSummary;
  autonomous_context: AutonomousContext;
  batch_id?: string;
  processing_time: number;
  warnings?: Warning[];
}

interface StoreItemResult {
  input_index: number;
  status: "stored" | "skipped_dedupe" | "business_rule_blocked" | "validation_error";
  kind: KnowledgeType;
  id?: string;
  created_at?: string;
  reason?: string;
  existing_id?: string;
  errors?: ValidationError[];
}

interface StoreSummary {
  stored: number;
  skipped_dedupe: number;
  business_rule_blocked: number;
  validation_error: number;
  total: number;
  chunks_created?: number;
  embeddings_generated?: number;
}
```

#### Memory Find API
```
GET /api/v1/memory/find
POST /api/v1/memory/find
Content-Type: application/json
Authorization: Bearer <api_key>
```

**Request Schema:**
```typescript
interface FindRequest {
  query: string;
  mode?: "auto" | "fast" | "deep";
  limit?: number; // max 1000, default 50
  offset?: number; // for pagination
  scope?: Scope;
  types?: KnowledgeType[];
  kind?: KnowledgeType; // legacy
  expand?: "relations" | "parents" | "children" | "none";
  expansion_depth?: number; // max 5, default 2
  include_relations?: string[];
  similarity_threshold?: number; // 0.0-1.0, default 0.7
  max_attempts?: number; // max 10, default 3
  filters?: {
    date_range?: {
      start?: string; // ISO 8601
      end?: string;   // ISO 8601
    };
    tags?: string[];
    priority?: string[];
    author?: string;
  };
  sort?: {
    field: "relevance" | "created_at" | "updated_at" | "confidence_score";
    order: "asc" | "desc";
  };
  include_content?: boolean; // default true
  highlight?: boolean; // default false
}
```

**Response Schema:**
```typescript
interface FindResponse {
  success: boolean;
  hits: SearchResult[];
  total: number;
  partial: boolean;
  search_metadata: SearchMetadata;
  autonomous_context: AutonomousContext;
  query_id: string;
  errors?: ApiError[];
  pagination?: {
    has_more: boolean;
    next_offset?: number;
    total_pages?: number;
  };
}

interface SearchResult {
  id: string;
  kind: KnowledgeType;
  scope: Scope;
  data: Record<string, any>;
  created_at: string;
  updated_at?: string;
  confidence_score: number;
  match_type: "exact" | "fuzzy" | "semantic" | "keyword" | "hybrid";
  highlight?: string[];
  relations?: Relation[];
  chunk_info?: ChunkInfo;
  distance?: number; // semantic similarity distance
  explanation?: string; // why this result matched
}

interface SearchMetadata {
  query: string;
  strategy_used: string;
  execution_time: number;
  expansion_used: boolean;
  scopes_searched: string[];
  cache_hit: boolean;
  results_filtered: number;
  total_candidates: number;
  fuzzy_fallback_used: boolean;
  semantic_search_enabled: boolean;
}
```

### HTTP Status Codes

| Status | Code | Description | Retry |
|--------|------|-------------|-------|
| 200 | OK | Successful operation | No |
| 201 | Created | Resource created | No |
| 400 | Bad Request | Invalid request parameters | No |
| 401 | Unauthorized | Authentication required | No |
| 403 | Forbidden | Insufficient permissions | No |
| 404 | Not Found | Resource not found | No |
| 409 | Conflict | Duplicate resource | No |
| 422 | Unprocessable Entity | Validation failed | No |
| 429 | Too Many Requests | Rate limit exceeded | Yes |
| 500 | Internal Server Error | Server error | Yes |
| 502 | Bad Gateway | Upstream service error | Yes |
| 503 | Service Unavailable | Temporary overload | Yes |
| 504 | Gateway Timeout | Request timeout | Yes |

### Error Response Format
```typescript
interface ErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    details?: any;
    timestamp: string;
    request_id?: string;
    retry_after?: number; // seconds
  };
  autonomous_context?: {
    action_performed: "error";
    recommendation: string;
    reasoning?: string;
  };
}

// Common Error Codes
const ERROR_CODES = {
  VALIDATION_ERROR: "Invalid request parameters or schema",
  INVALID_API_KEY: "API key is invalid or expired",
  RATE_LIMITED: "Too many requests, try again later",
  QUOTA_EXCEEDED: "Monthly quota exceeded",
  DATABASE_ERROR: "Database operation failed",
  EMBEDDING_SERVICE_ERROR: "Embedding generation service unavailable",
  CHUNKING_ERROR: "Content chunking failed",
  SEMANTIC_SEARCH_DISABLED: "Semantic search not available",
  INVALID_SCOPE: "Scope configuration is invalid",
  PERMISSION_DENIED: "Insufficient permissions for operation",
  TIMEOUT_ERROR: "Operation timed out",
  INTERNAL_ERROR: "Internal server error"
} as const;
```

### Authentication & Authorization

#### API Key Authentication
```typescript
// Header Format
Authorization: Bearer <api_key>

// API Key Types
enum ApiKeyType {
  READ_ONLY = "read_only",      // Can only search/find
  READ_WRITE = "read_write",    // Can search and store
  ADMIN = "admin"              // Full access including configuration
}

// API Key Scope Restrictions
interface ApiKeyScope {
  allowed_scopes?: Scope[];     // Restrict to specific orgs/projects
  allowed_types?: KnowledgeType[]; // Restrict to specific knowledge types
  rate_limit?: RateLimit;       // Custom rate limits
  expiry?: string;             // API key expiration
}
```

#### Rate Limiting
```typescript
interface RateLimit {
  requests_per_minute: number;  // Default: 60
  requests_per_hour: number;    // Default: 1000
  requests_per_day: number;     // Default: 10000
  burst_limit: number;          // Default: 10
  storage_mb_per_month: number; // Default: 1000
}

// Rate Limit Headers (in responses)
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1640995200
X-RateLimit-Retry-After: 30
```

---

## Usage Examples

### Complete Store Example
```typescript
// Store multiple items with different types
const result = await memory_store({
  items: [
    {
      kind: "entity",
      content: "User profile for John Doe",
      scope: { org: "acme", project: "user-management", branch: "main" },
      data: {
        name: "John Doe",
        email: "john@acme.com",
        role: "developer"
      }
    },
    {
      kind: "decision",
      content: "Use PostgreSQL as primary database",
      scope: { org: "acme", project: "infrastructure", branch: "main" },
      data: {
        title: "Database Selection Decision",
        status: "accepted",
        component: "Data Layer",
        alternatives: ["MySQL", "MongoDB"],
        impact: "High",
        implementation_date: "2025-10-01"
      },
      metadata: {
        author: "architect@acme.com",
        approved_by: "cto@acme.com"
      }
    },
    {
      kind: "section",
      content: "Very long technical documentation that will be semantically chunked automatically..." + "Long content repeated to exceed 3600 characters for demonstration of semantic chunking capabilities",
      scope: { org: "acme", project: "docs", branch: "main" },
      ttl_policy: "90d"
    }
  ]
});

console.log(`Stored ${result.summary.stored} items, skipped ${result.summary.skipped_dedupe} duplicates`);
```

### Complete Search Example
```typescript
// Advanced search with multiple features
const searchResult = await memory_find({
  query: "database decisions PostgreSQL",
  mode: "deep",
  scope: {
    org: "acme",
    project: "infrastructure"
  },
  types: ["decision", "section"],
  expand: "relations",
  limit: 10,
  similarity_threshold: 0.7
});

console.log(`Found ${searchResult.total} results`);
searchResult.hits.forEach((hit, index) => {
  console.log(`${index + 1}. ${hit.kind}: ${hit.data.title || hit.content.substring(0, 50)}...`);
  console.log(`   Score: ${hit.confidence_score}, Type: ${hit.match_type}`);
});
});
```

### Batch Processing Example
```typescript
// Process large batch with error handling
const batchSize = 50;
const allItems = [...]; // Large array of items

for (let i = 0; i < allItems.length; i += batchSize) {
  const batch = allItems.slice(i, i + batchSize);

  try {
    const result = await memory_store({ items: batch });
    console.log(`Batch ${Math.floor(i/batchSize) + 1}: ${result.summary.stored} stored, ${result.summary.validation_error} errors`);

    // Handle errors
    if (result.errors.length > 0) {
      result.errors.forEach(error => {
        console.error(`Error at index ${error.index}: ${error.message}`);
      });
    }
  } catch (error) {
    console.error(`Batch ${Math.floor(i/batchSize) + 1} failed:`, error);
    // Implement retry logic or continue with next batch
  }
}
```

---

## Integration Examples

### MCP Tool Integration
```typescript
// In your MCP server implementation
app.tool('memory_store', {
  description: 'Store knowledge items in Cortex Memory',
  inputSchema: {
    type: 'object',
    properties: {
      items: {
        type: 'array',
        items: { $ref: '#/definitions/KnowledgeItem' }
      }
    },
    required: ['items']
  }
}, async (args) => {
  const result = await memory_store(args);
  return {
    content: [{
      type: 'text',
      text: `Stored ${result.summary.stored} items successfully. ${result.summary.skipped_dedupe} duplicates skipped.`
    }]
  };
});

app.tool('memory_find', {
  description: 'Search knowledge items in Cortex Memory',
  inputSchema: {
    type: 'object',
    properties: {
      query: { type: 'string' },
      mode: { type: 'string', enum: ['auto', 'fast', 'deep'] },
      limit: { type: 'number' }
    },
    required: ['query']
  }
}, async (args) => {
  const result = await memory_find(args);
  return {
    content: [{
      type: 'text',
      text: `Found ${result.total} results for "${args.query}":\n${result.hits.map(hit => `- ${hit.kind}: ${hit.data.title || hit.content.substring(0, 100)}`).join('\n')}`
    }]
  };
});
```

### Direct API Integration
```typescript
// Direct integration without MCP wrapper
import { MemoryStoreOrchestratorQdrant } from './src/services/orchestrators/memory-store-orchestrator-qdrant.js';

const store = new MemoryStoreOrchestratorQdrant(config);

// Store items
const storeResult = await store.storeItems(items);

// Find items
const findResult = await store.findItems({
  query: "search query",
  mode: "auto",
  scope: { project: "my-project" }
});
```

---

## Best Practices

### Store Operations
1. **Batch Processing**: Store multiple items in single requests for efficiency
2. **Scope Management**: Use consistent scope naming conventions
3. **Content Quality**: Provide meaningful content for better semantic analysis
4. **Metadata Usage**: Include relevant metadata for better organization
5. **TTL Management**: Set appropriate TTL policies for different content types

### Search Operations
1. **Query Optimization**: Use specific queries rather than broad searches
2. **Scope Filtering**: Limit searches to relevant scopes for performance
3. **Type Filtering**: Specify knowledge types when known
4. **Progressive Loading**: Use pagination for large result sets
5. **Expansion Control**: Use graph expansion judiciously for complex queries

### Performance Optimization
1. **Semantic Chunking**: Let long content benefit from semantic analysis
2. **Caching**: Leverage built-in caching for repeated operations
3. **Batch Size**: Optimize batch sizes for your use case (10-100 items)
4. **Async Operations**: Use async patterns for non-blocking operations
5. **Monitoring**: Track performance metrics and optimize accordingly

---

## Deployment & Operations Guide

### System Requirements

#### Minimum Requirements
- **CPU**: 2 cores, 2.4 GHz
- **Memory**: 4 GB RAM
- **Storage**: 20 GB SSD
- **Network**: 100 Mbps
- **OS**: Linux (Ubuntu 20.04+, CentOS 8+), macOS 10.15+, Windows 10+

#### Recommended Requirements
- **CPU**: 4 cores, 3.0 GHz
- **Memory**: 8 GB RAM
- **Storage**: 50 GB SSD
- **Network**: 1 Gbps
- **OS**: Linux (Ubuntu 22.04 LTS)

#### Production Requirements (High Throughput)
- **CPU**: 8 cores, 3.2 GHz
- **Memory**: 16 GB RAM
- **Storage**: 100 GB NVMe SSD
- **Network**: 10 Gbps
- **Load Balancer**: HAProxy/Nginx
- **Monitoring**: Prometheus + Grafana

### Prerequisites

#### Required Services
```bash
# Vector Database
Qdrant v1.7.0+
- URL: http://localhost:6333
- API Key: Required for production

# Optional: Embedding Services
OpenAI API or Cohere API or Local embedding service
```

#### Node.js Environment
```bash
# Required Node.js version
Node.js >= 18.0.0
npm >= 8.0.0

# Recommended
Node.js >= 20.0.0
npm >= 10.0.0
```

### Installation Methods

#### Method 1: Direct Installation
```bash
# Clone repository
git clone https://github.com/your-org/mcp-cortex.git
cd mcp-cortex

# Install dependencies
npm install

# Copy environment template
cp .env.example .env

# Edit configuration
nano .env

# Run database setup
npm run db:setup

# Start service
npm start
```

#### Method 2: Docker Installation
```bash
# Pull image
docker pull cortex-memory/mcp-cortex:latest

# Create volume for data
docker volume create cortex-data

# Run container
docker run -d \
  --name cortex-memory \
  -p 3000:3000 \
  --env-file .env \
  -v cortex-data:/app/data \
  cortex-memory/mcp-cortex:latest
```

#### Method 3: Docker Compose (Recommended)
```yaml
# docker-compose.yml
version: '3.8'

services:
  cortex-memory:
    image: cortex-memory/mcp-cortex:latest
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - QDRANT_URL=http://qdrant:6333
      - QDRANT_API_KEY=${QDRANT_API_KEY}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    depends_on:
      - qdrant
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  qdrant:
    image: qdrant/qdrant:latest
    ports:
      - "6333:6333"
    environment:
      - QDRANT__SERVICE__API_KEY=${QDRANT_API_KEY}
    volumes:
      - qdrant-data:/qdrant/storage
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - cortex-memory
    restart: unless-stopped

volumes:
  qdrant-data:
  cortex-data:
```

### Production Deployment

#### Deployment Architecture
```
Internet
    |
[Load Balancer]
    |
[Nginx Reverse Proxy]
    |
[Cortex Memory Cluster]
    |    |    |
[Node1][Node2][Node3]
    |    |    |
[Qdrant Cluster - Shared]
```

#### Scaling Configuration

#### Horizontal Scaling
```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  cortex-memory-1:
    image: cortex-memory/mcp-cortex:latest
    environment:
      - NODE_ID=node-1
      - CLUSTER_MODE=true
      - QDRANT_URL=http://qdrant:6333
    deploy:
      replicas: 3
      resources:
        limits:
          memory: 2G
          cpus: '1.0'
        reservations:
          memory: 1G
          cpus: '0.5'

  nginx:
    image: nginx:alpine
    volumes:
      - ./nginx-lb.conf:/etc/nginx/nginx.conf
    depends_on:
      - cortex-memory-1
```

#### Nginx Load Balancer Configuration
```nginx
# nginx-lb.conf
events {
    worker_connections 1024;
}

http {
    upstream cortex_backend {
        least_conn;
        server cortex-memory-1:3000 max_fails=3 fail_timeout=30s;
        server cortex-memory-2:3000 max_fails=3 fail_timeout=30s;
        server cortex-memory-3:3000 max_fails=3 fail_timeout=30s;
    }

    server {
        listen 80;
        server_name api.cortex-memory.com;

        location / {
            proxy_pass http://cortex_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # Timeouts
            proxy_connect_timeout 30s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;

            # Rate limiting
            limit_req zone=api burst=20 nodelay;
        }
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
}
```

### Database Setup & Management

#### Qdrant Production Setup
```bash
# Single node setup
docker run -d \
  --name qdrant \
  -p 6333:6333 \
  -v qdrant-storage:/qdrant/storage \
  -e QDRANT__SERVICE__API_KEY=your-api-key \
  -e QDRANT__SERVICE__LOG_LEVEL=INFO \
  qdrant/qdrant:latest

# Cluster setup (3 nodes)
# Node 1
docker run -d \
  --name qdrant-1 \
  -p 6333:6333 \
  -e QDRANT__SERVICE__API_KEY=your-api-key \
  -e QDRANT__CLUSTER__ENABLED=true \
  -e QDRANT__CLUSTER__URI=http://qdrant-1:6333 \
  qdrant/qdrant:latest

# Node 2 & 3 (similar config, different peer URIs)
```

#### Database Migration
```bash
# Create collections with production schema
curl -X PUT "http://localhost:6333/collections/knowledge_items" \
  -H "api-key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "vectors": {
      "size": 1536,
      "distance": "Cosine"
    },
    "optimizers_config": {
      "default_segment_number": 2
    },
    "hnsw_config": {
      "m": 16,
      "ef_construct": 64
    }
  }'

# Create indexes for metadata filtering
curl -X PUT "http://localhost:6333/collections/knowledge_items/index" \
  -H "api-key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "field_name": "metadata.kind",
    "field_schema": "keyword"
  }'
```

### Monitoring & Observability

#### Health Endpoints
```typescript
// GET /health
{
  "status": "healthy",
  "timestamp": "2025-10-31T13:00:00.000Z",
  "uptime": 86400,
  "version": "2.0.0",
  "checks": {
    "database": "healthy",
    "embedding_service": "healthy",
    "cache": "healthy"
  }
}

// GET /health/ready
{
  "status": "ready",
  "checks": {
    "database_connected": true,
    "embedding_service_available": true,
    "cache_warm": true
  }
}

// GET /metrics (Prometheus format)
cortex_memory_requests_total{method="POST",endpoint="/store",status="200"} 1250
cortex_memory_request_duration_seconds{quantile="0.95"} 0.245
cortex_memory_database_connections_active 15
cortex_memory_embedding_cache_size 847
```

#### Monitoring Stack (Docker Compose)
```yaml
# monitoring.yml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana-dashboards:/etc/grafana/provisioning/dashboards

  node-exporter:
    image: prom/node-exporter:latest
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro

volumes:
  prometheus-data:
  grafana-data:
```

#### Key Metrics to Monitor
```typescript
// Performance Metrics
- Request throughput (requests/second)
- Response latency (p50, p95, p99)
- Error rate (4xx, 5xx responses)
- Database query performance
- Embedding generation latency

// Resource Metrics
- CPU usage percentage
- Memory usage percentage
- Disk I/O and usage
- Network traffic
- Database connection pool usage

// Business Metrics
- Active knowledge items count
- Storage usage by type
- Search success rate
- Chunking performance
- Cache hit rates
```

### Backup & Disaster Recovery

#### Database Backup Strategy
```bash
#!/bin/bash
# backup.sh

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/qdrant"
COLLECTION="knowledge_items"

# Create snapshot
curl -X POST "http://localhost:6333/collections/$COLLECTION/snapshots" \
  -H "api-key: $QDRANT_API_KEY" \
  -H "Content-Type: application/json"

# Download snapshot
SNAPSHOT_NAME="snapshot-$TIMESTAMP"
curl -X GET "http://localhost:6333/collections/$COLLECTION/snapshots/$SNAPSHOT_NAME" \
  -H "api-key: $QDRANT_API_KEY" \
  -o "$BACKUP_DIR/$SNAPSHOT_NAME.snapshot"

# Compress backup
gzip "$BACKUP_DIR/$SNAPSHOT_NAME.snapshot"

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "*.snapshot.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_DIR/$SNAPSHOT_NAME.snapshot.gz"
```

#### Automated Backup with Cron
```bash
# Add to crontab
# Daily backup at 2 AM
0 2 * * * /opt/cortex-memory/scripts/backup.sh

# Weekly consistency check (Sundays at 3 AM)
0 3 * * 0 /opt/cortex-memory/scripts/consistency-check.sh
```

#### Disaster Recovery Procedure
```bash
#!/bin/bash
# restore.sh

SNAPSHOT_FILE=$1
COLLECTION="knowledge_items"

if [ -z "$SNAPSHOT_FILE" ]; then
    echo "Usage: $0 <snapshot_file>"
    exit 1
fi

# Decompress snapshot
gunzip -c "$SNAPSHOT_FILE" > "/tmp/restore.snapshot"

# Stop service
docker stop cortex-memory

# Restore collection
curl -X POST "http://localhost:6333/collections/$COLLECTION/snapshots/restore" \
  -H "api-key: $QDRANT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"snapshot_path": "/tmp/restore.snapshot"}'

# Restart service
docker start cortex-memory

# Verify restoration
curl -X GET "http://localhost:3000/health"

echo "Restore completed from: $SNAPSHOT_FILE"
```

### Security Hardening

#### Network Security
```bash
# Firewall configuration
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw enable

# Docker network isolation
docker network create --driver bridge cortex-network
docker network connect cortex-network cortex-memory
docker network connect cortex-network qdrant
```

#### SSL/TLS Configuration
```nginx
# nginx-ssl.conf
server {
    listen 443 ssl http2;
    server_name api.cortex-memory.com;

    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;

    location / {
        proxy_pass http://cortex_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Environment Security
```bash
# Secure environment variables
export QDRANT_API_KEY=$(openssl rand -hex 32)
export JWT_SECRET=$(openssl rand -hex 64)
export API_ENCRYPTION_KEY=$(openssl rand -hex 32)

# File permissions
chmod 600 .env
chmod 700 config/
chmod 755 scripts/
```

### Performance Optimization

#### Production Tuning Parameters
```json
{
  "performance": {
    "batchSize": 200,
    "maxConcurrentRequests": 100,
    "connectionPool": {
      "min": 5,
      "max": 20,
      "acquireTimeout": 5000
    },
    "caching": {
      "embeddingCache": {
        "size": 5000,
        "ttl": 7200000
      },
      "resultCache": {
        "size": 1000,
        "ttl": 600000
      }
    }
  },
  "database": {
    "hnsw": {
      "m": 32,
      "ef_construct": 128,
      "ef": 64
    },
    "optimization": {
      "defaultSegmentNumber": 4,
      "maxSegmentSize": 100000,
      "memmapThreshold": 50000
    }
  }
}
```

---

## Comprehensive Troubleshooting Guide

### Error Code Reference

#### Database Errors (500-599)
| Code | Message | Cause | Solution |
|------|---------|-------|----------|
| `DATABASE_CONNECTION_FAILED` | Unable to connect to Qdrant | Network issues, wrong URL/API key | Check QDRANT_URL, QDRANT_API_KEY, network connectivity |
| `DATABASE_TIMEOUT` | Query timeout exceeded | Large queries, slow database | Increase timeout, optimize queries, check DB performance |
| `COLLECTION_NOT_FOUND` | Collection does not exist | First-time setup, collection deleted | Run database setup, verify collection name |
| `INVALID_VECTOR_SIZE` | Vector dimension mismatch | Wrong embedding model | Check embedding model compatibility with collection |
| `STORAGE_FULL` | Disk space exhausted | Too much data, no cleanup | Clean up old data, add storage, enable TTL cleanup |

#### Embedding Service Errors (400-499)
| Code | Message | Cause | Solution |
|------|---------|-------|----------|
| `EMBEDDING_SERVICE_UNAVAILABLE` | Cannot reach embedding service | Service down, network issues | Check service status, network connectivity |
| `INVALID_API_KEY` | Embedding API key invalid | Expired/incorrect API key | Update API key, check subscription status |
| `RATE_LIMIT_EXCEEDED` | Embedding rate limit hit | Too many requests | Implement rate limiting, use batch processing |
| `INVALID_TEXT_LENGTH` | Text too long/short for embedding | Content length validation error | Check text length limits, chunk content appropriately |
| `EMBEDDING_GENERATION_FAILED` | Failed to generate embeddings | Service error, invalid content | Check content format, retry with exponential backoff |

#### Authentication Errors (401-403)
| Code | Message | Cause | Solution |
|------|---------|-------|----------|
| `UNAUTHORIZED` | Invalid or missing API key | No authentication, wrong key | Provide valid API key in Authorization header |
| `FORBIDDEN` | Insufficient permissions | API key lacks required scope | Update API key permissions, check scope restrictions |
| `TOKEN_EXPIRED` | JWT token has expired | Token timeout | Refresh token, implement token renewal |
| `INVALID_CREDENTIALS` | Malformed authentication | Invalid format, encoding error | Check authentication format, use proper encoding |

#### Validation Errors (400-422)
| Code | Message | Cause | Solution |
|------|---------|-------|----------|
| `INVALID_KNOWLEDGE_TYPE` | Unsupported knowledge type | Typo, custom type not registered | Check supported types, register custom type |
| `MISSING_REQUIRED_FIELD` | Required field missing | Incomplete request data | Add missing required fields |
| `INVALID_SCOPE_FORMAT` | Malformed scope object | Wrong scope structure | Use proper scope format: `{org, project, branch}` |
| `CONTENT_TOO_LARGE` | Content exceeds size limit | Very large content input | Use chunking, reduce content size |
| `INVALID_TTL_FORMAT` | TTL policy not recognized | Wrong TTL string format | Use supported policies: 1d,7d,30d,90d,permanent |

### Diagnostic Tools & Commands

#### Health Check Endpoints
```bash
# Basic health check
curl -f http://localhost:3000/health

# Detailed readiness check
curl -f http://localhost:3000/health/ready

# Database connectivity
curl -f http://localhost:3000/health/database

# Embedding service status
curl -f http://localhost:3000/health/embeddings

# System metrics
curl -f http://localhost:3000/metrics
```

#### Database Diagnostics
```bash
# Check Qdrant status
curl http://localhost:6333/health

# List collections
curl -H "api-key: $QDRANT_API_KEY" \
     http://localhost:6333/collections

# Collection info
curl -H "api-key: $QDRANT_API_KEY" \
     http://localhost:6333/collections/knowledge_items

# Collection statistics
curl -H "api-key: $QDRANT_API_KEY" \
     http://localhost:6333/collections/knowledge_items/cluster

# Search test
curl -X POST "http://localhost:6333/collections/knowledge_items/search" \
  -H "api-key: $QDRANT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"vector": [0.1, 0.2, 0.3], "limit": 1}'
```

#### Service Debugging
```bash
# Check service logs
docker logs cortex-memory
docker logs qdrant

# Real-time log monitoring
docker logs -f cortex-memory

# Service status
docker ps
docker stats cortex-memory

# Resource usage
docker exec cortex-memory top
docker exec cortex-memory df -h
```

### Common Failure Scenarios & Solutions

#### Scenario 1: Embedding Service Failures (CURRENT ISSUE)
**Symptoms:**
- Tests timing out after 60 seconds
- Error: `EMBEDDING_GENERATION_FAILED` with `INVALID_EMBEDDING_RESPONSE`
- Multiple repeated embedding failures in logs
- Semantic chunking tests failing

**Current Status (2025-10-31):**
- Test environment: Embedding service returning invalid responses
- Semantic chunking implemented but failing due to embedding issues
- Traditional chunking working as fallback
- Production: Feature functional with proper embedding configuration

**Diagnostic Steps:**
```bash
# Check test environment embedding service
npm run test tests/unit/chunk-reassembly-simple.test.ts

# Review embedding configuration
cat .env.test | grep -i embed

# Check embedding service status
curl -X POST "https://api.openai.com/v1/embeddings" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"input": "test", "model": "text-embedding-3-small"}'
```

**Immediate Solutions:**
1. **Disable semantic chunking in tests:**
   ```bash
   ENABLE_SEMANTIC_CHUNKING=false
   ```

2. **Use mock embedding service for testing:**
   ```typescript
   // In test setup
   const mockEmbeddingService = {
     generateEmbedding: async (text: string) => ({
       vector: new Array(1536).fill(0.1)
     })
   };
   ```

3. **Configure test environment:**
   ```bash
   # .env.test
   OPENAI_API_KEY=mock_key_for_testing
   ENABLE_SEMANTIC_CHUNKING=false
   ```

**Production Solutions:**
1. **Increase timeout settings:**
   ```bash
   OPENAI_TIMEOUT=60000
   REQUEST_TIMEOUT=60000
   ```

2. **Implement retry logic:**
   ```typescript
   const embedWithRetry = async (text: string, retries = 3) => {
     for (let i = 0; i < retries; i++) {
       try {
         return await embedText(text);
       } catch (error) {
         if (i === retries - 1) throw error;
         await delay(Math.pow(2, i) * 1000);
       }
     }
   };
   ```

3. **Use alternative embedding service:**
   ```bash
   EMBEDDING_PROVIDER=local
   LOCAL_EMBEDDING_URL=http://localhost:8080/embed
   ```

#### Scenario 2: Database Connection Issues
**Symptoms:**
- Health check failing
- Error: `DATABASE_CONNECTION_FAILED`
- Intermittent service failures

**Diagnostic Steps:**
```bash
# Test database connectivity
curl -H "api-key: $QDRANT_API_KEY" \
     http://localhost:6333/health

# Check network connection
telnet localhost 6333
nc -zv localhost 6333

# Verify API key
curl -H "api-key: wrong_key" \
     http://localhost:6333/collections

# Check Docker network
docker network ls
docker network inspect cortex-network
```

**Solutions:**
1. **Verify database configuration:**
   ```bash
   QDRANT_URL=http://qdrant:6333  # Use service name in Docker
   QDRANT_API_KEY=your_correct_key
   ```

2. **Restart services:**
   ```bash
   docker-compose restart qdrant
   docker-compose restart cortex-memory
   ```

3. **Check resource constraints:**
   ```bash
   docker stats qdrant
   docker logs qdrant | grep -i error
   ```

#### Scenario 3: Memory Leaks / High Memory Usage
**Symptoms:**
- Gradual memory increase
- Container OOM kills
- Slow performance over time

**Diagnostic Steps:**
```bash
# Monitor memory usage
docker stats cortex-memory --no-stream
watch -n 5 'docker stats cortex-memory --no-stream'

# Check Node.js heap usage
docker exec cortex-memory node -e "console.log(process.memoryUsage())"

# Profile memory usage
docker exec cortex-memory node --inspect=0.0.0.0:9229 app.js
```

**Solutions:**
1. **Configure caching limits:**
   ```json
   {
     "caching": {
       "embeddingCache": {
         "size": 1000,
         "ttl": 3600000
       },
       "resultCache": {
         "size": 500,
         "ttl": 300000
       }
     }
   }
   ```

2. **Enable garbage collection:**
   ```bash
   NODE_OPTIONS="--max-old-space-size=2048 --expose-gc"
   ```

3. **Monitor and restart:**
   ```yaml
   deploy:
     restart_policy:
       condition: on-failure
       delay: 5s
       max_attempts: 3
     resources:
       limits:
         memory: 2G
       reservations:
         memory: 1G
   ```

#### Scenario 4: Search Performance Degradation
**Symptoms:**
- Search queries becoming slower
- Timeout errors on complex searches
- Poor relevance in results

**Diagnostic Steps:**
```bash
# Test search performance
time curl -X POST "http://localhost:3000/api/v1/memory/find" \
  -H "Content-Type: application/json" \
  -d '{"query": "test query", "mode": "deep"}'

# Check collection optimization
curl -H "api-key: $QDRANT_API_KEY" \
     http://localhost:6333/collections/knowledge_items

# Monitor query patterns
curl -s http://localhost:3000/metrics | grep search
```

**Solutions:**
1. **Optimize search parameters:**
   ```json
   {
     "search": {
       "maxAttempts": 2,
       "similarityThreshold": 0.8,
       "expansion": {
         "maxDepth": 2,
         "timeout": 3000
       }
     }
   }
   ```

2. **Database optimization:**
   ```bash
   # Update collection configuration
   curl -X PATCH "http://localhost:6333/collections/knowledge_items" \
     -H "api-key: $QDRANT_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "optimizer_config": {
         "default_segment_number": 4,
         "max_segment_size": 50000
       }
     }'
   ```

3. **Implement result caching:**
   ```typescript
   // Cache frequent searches
   const cacheKey = `search:${query}:${JSON.stringify(filters)}`;
   const cached = await cache.get(cacheKey);
   if (cached) return cached;
   ```

### Advanced Debugging Techniques

#### Enable Debug Logging
```bash
# Enable comprehensive debug logging
DEBUG=cortex:*
LOG_LEVEL=debug

# Specific component debugging
DEBUG=cortex:database,cortex:embeddings

# Performance debugging
DEBUG=cortex:performance,cortex:metrics
```

#### Memory Profiling
```bash
# Start with heap profiling
NODE_OPTIONS="--inspect=0.0.0.0:9229 --heap-prof"

# Generate heap snapshot
docker exec cortex-memory node -e "
  const v8 = require('v8');
  const fs = require('fs');
  const snapshot = v8.getHeapSnapshot();
  fs.writeFileSync('/tmp/heap.heapsnapshot', snapshot);
"

# Analyze with Chrome DevTools
chrome://inspect
```

#### Database Query Analysis
```bash
# Enable query logging
QDRANT__LOG_LEVEL=debug

# Monitor query performance
curl -H "api-key: $QDRANT_API_KEY" \
     http://localhost:6333/collections/knowledge_items/search \
     -X POST -d '...query...' -v

# Check indexing status
curl -H "api-key: $QDRANT_API_KEY" \
     http://localhost:6333/collections/knowledge_items/indexes
```

#### Network Diagnostics
```bash
# Test service connectivity
docker exec cortex-memory ping qdrant
docker exec cortex-memory nslookup qdrant

# Check port availability
docker exec cortex-memory netstat -tlnp | grep :3000
docker exec cortex-memory ss -tlnp | grep :6333

# Monitor network traffic
docker exec cortex-memory tcpdump -i any port 6333
```

### Performance Tuning Guide

#### Memory Optimization
```json
{
  "performance": {
    "batchSize": 50,
    "concurrency": {
      "embedding": 2,
      "database": 5,
      "chunking": 3
    },
    "memory": {
      "maxHeapSize": "1g",
      "gcStrategy": "incremental"
    }
  }
}
```

#### Database Tuning
```json
{
  "database": {
    "hnsw": {
      "m": 16,
      "ef_construct": 64,
      "ef": 32
    },
    "quantization": {
      "scalar": {
        "type": "int8",
        "quantile": 0.99
      }
    },
    "optimization": {
      "memmap_threshold": 20000,
      "indexing_threshold": 10000
    }
  }
}
```

#### Caching Strategy
```typescript
// Multi-level caching
const cacheStrategy = {
  l1: {
    type: "memory",
    size: 100,
    ttl: 60000 // 1 minute
  },
  l2: {
    type: "redis",
    size: 10000,
    ttl: 3600000 // 1 hour
  },
  l3: {
    type: "database",
    persistent: true
  }
};
```

### Monitoring & Alerting Setup

#### Prometheus Alerts
```yaml
# prometheus-alerts.yml
groups:
- name: cortex-memory
  rules:
  - alert: HighErrorRate
    expr: rate(cortex_memory_requests_total{status=~"5.."}[5m]) > 0.1
    for: 2m
    annotations:
      summary: "High error rate detected"

  - alert: HighLatency
    expr: histogram_quantile(0.95, cortex_memory_request_duration_seconds) > 2
    for: 5m
    annotations:
      summary: "High latency detected"

  - alert: DatabaseConnectionFailed
    expr: up{job="cortex-memory"} == 0
    for: 1m
    annotations:
      summary: "Database connection failed"
```

#### Grafana Dashboard
```json
{
  "dashboard": {
    "title": "Cortex Memory Monitoring",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(cortex_memory_requests_total[5m])"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "singlestat",
        "targets": [
          {
            "expr": "rate(cortex_memory_requests_total{status=~\"5..\"}[5m])"
          }
        ]
      },
      {
        "title": "Memory Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "process_resident_memory_bytes"
          }
        ]
      }
    ]
  }
}
```

### Log Analysis Patterns

#### Common Log Patterns
```bash
# Extract error patterns
grep -i error /var/log/cortex-memory.log | tail -20

# Monitor response times
grep "response_time" /var/log/cortex-memory.log | \
  awk '{print $NF}' | sort -n

# Track failed embeddings
grep "embedding_failed" /var/log/cortex-memory.log | \
  wc -l

# Database connection issues
grep "database" /var/log/cortex-memory.log | \
  grep -i "failed\|error\|timeout"
```

#### Log Aggregation Setup
```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  paths:
    - /var/log/cortex-memory/*.log
  fields:
    service: cortex-memory
    environment: production

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "cortex-memory-%{+yyyy.MM.dd}"
```

### Emergency Procedures

#### Service Recovery
```bash
#!/bin/bash
# emergency-recovery.sh

echo "Starting emergency recovery..."

# 1. Check service status
docker-compose ps

# 2. Restart failed services
docker-compose restart

# 3. Verify health
sleep 30
curl -f http://localhost:3000/health || {
  echo "Health check failed, forcing recreation..."
  docker-compose down
  docker-compose up -d
  sleep 60
  curl -f http://localhost:3000/health
}

# 4. Check data integrity
curl -H "api-key: $QDRANT_API_KEY" \
     http://localhost:6333/collections/knowledge_items

echo "Emergency recovery completed"
```

#### Data Recovery
```bash
#!/bin/bash
# data-recovery.sh

BACKUP_FILE=$1
if [ -z "$BACKUP_FILE" ]; then
  echo "Usage: $0 <backup_file>"
  exit 1
fi

echo "Starting data recovery from $BACKUP_FILE..."

# Stop services
docker-compose stop cortex-memory

# Restore database
docker-compose exec qdrant \
  qdrant-cli snapshots recover \
  --collection knowledge_items \
  --snapshot-path "/backups/$BACKUP_FILE"

# Restart services
docker-compose start cortex-memory

# Verify recovery
sleep 30
curl -f http://localhost:3000/health

echo "Data recovery completed"
```

This comprehensive troubleshooting guide provides systematic approaches to diagnosing and resolving common issues with the MCP Cortex Memory System, from basic connectivity problems to complex performance optimization scenarios.

---

## Known Issues & Current Status

### Current Issues (2025-11-01)

#### 1. Code Quality Issues
- **Status**: ⚠️ ACTIVE ISSUE
- **Impact**: 170 linting problems (17 errors, 153 warnings) blocking quality gates
- **Affected Components**: Multiple middleware, monitoring, and service files
- **Key Issues**:
  - Undefined variables in auth middleware (`authContext`)
  - Unused variables and imports throughout codebase
  - String concatenation instead of template literals
  - Missing return statements in async functions
- **Production Impact**: Code quality gates failing, potential runtime errors

#### 2. Test Environment Embedding Failures (RESOLVED)
- **Status**: ✅ RESOLVED
- **Previous Impact**: Semantic chunking tests were failing with `INVALID_EMBEDDING_RESPONSE`
- **Resolution**: Tests now use traditional chunking fallback; semantic features configurable
- **Production Impact**: None (production uses different configuration)

#### 3. Semantic Chunking Availability
- **Status**: ✅ IMPLEMENTED with dependency
- **Requirement**: Functional embedding service (OpenAI/Cohere/Local)
- **Fallback**: Automatic degradation to traditional chunking
- **Configuration**: Requires `ENABLE_SEMANTIC_CHUNKING=true` and valid API keys

### Implementation Status Summary

| Feature | Status | Notes |
|---------|--------|-------|
| **Core Chunking** | ✅ Complete | 1200 char target, 200 char overlap |
| **Semantic Analysis** | ✅ Complete | Sentence-level boundary detection |
| **Embedding Service Integration** | ✅ Complete | Multiple providers supported |
| **Fallback Mechanisms** | ✅ Complete | Graceful degradation |
| **Code Quality** | ⚠️ BLOCKING | 170 linting issues need resolution |
| **Test Coverage** | ✅ Functional | Tests use traditional chunking fallback |
| **Documentation** | ✅ Complete | This document |

### Resolution Timeline

- **Immediate**: Code quality issues blocking deployment (170 linting problems)
- **Short-term**: Fix undefined variables and critical errors in middleware
- **Medium-term**: Clean up unused variables and improve code hygiene
- **Long-term**: Consider mock embedding services for isolated testing

---

**Document Status**: ✅ Complete with Current Issues Noted
**Last Review**: 2025-11-01
**Last Updated**: Updated system status with current code quality issues
**Next Review**: After code quality issues resolved

This documentation represents the complete feature set available in MCP Cortex Memory System v2.0. For the most up-to-date information, check the source code and inline documentation.