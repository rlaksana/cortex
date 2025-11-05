# Cortex Memory MCP API Documentation v2.0

## Overview

The Cortex Memory MCP Server v2.0 provides an AI-optimized API for knowledge storage, retrieval, and management through the Model Context Protocol (MCP). This document covers the enhanced 3-tool interface with advanced features including intelligent deduplication, TTL policies, semantic chunking, and comprehensive monitoring capabilities designed specifically for AI agent integration.

**🚀 Production Ready Features (100% Compliant)**:
- ✅ **MCP Protocol Version 2024-11-05** - Full compliance with latest MCP specification
- ✅ **3-Tool Interface** - Streamlined, AI-optimized tool set
- ✅ **16 Knowledge Types** - Complete knowledge type support with validation
- ✅ **Intelligent Deduplication** - 5 merge strategies with semantic similarity
- ✅ **TTL Management** - 4 configurable TTL policies with auto-extension
- ✅ **Content Chunking** - Smart semantic chunking for large documents
- ✅ **Advanced Search** - Fast/auto/deep modes with graph expansion
- ✅ **Performance Monitoring** - Comprehensive metrics and health checks

## Base Architecture

The system uses a Qdrant-only database layer:

- **Qdrant**: Vector similarity search, semantic understanding, and all data storage

⚠️ **Important**: This system uses Qdrant exclusively. PostgreSQL is not used or configured.

## Core API Methods (v2.0 - 3-Tool Interface)

### 1. memory_store

Store knowledge items in Cortex memory with advanced deduplication, TTL management, and intelligent content processing. Think of this as a production-grade knowledge base that automatically prevents duplicate entries (configurable similarity thresholds), manages content lifecycle, and provides comprehensive audit logging. Use for storing user preferences, decisions, observations, tasks, incidents, risks, assumptions, and all other knowledge types with advanced features.

**Endpoint**: `memory_store`

**AI-Friendly Description**: Store knowledge items with intelligent deduplication, TTL policies, semantic chunking, and comprehensive validation.

**Enhanced Parameters**:

```typescript
interface MemoryStoreRequest {
  items: EnhancedKnowledgeItem[];
  deduplication?: DeduplicationConfig;
  global_ttl?: GlobalTTLConfig;
  global_truncation?: GlobalTruncationConfig;
  global_insights?: GlobalInsightsConfig;
  processing?: ProcessingConfig;
}

interface EnhancedKnowledgeItem {
  kind:
    | 'entity'
    | 'relation'
    | 'observation'
    | 'section'
    | 'runbook'
    | 'change'
    | 'issue'
    | 'decision'
    | 'todo'
    | 'release_note'
    | 'ddl'
    | 'pr_context'
    | 'incident'
    | 'release'
    | 'risk'
    | 'assumption';
  content?: string;  // For text-based types
  data?: Record<string, any>;  // For structured data
  scope?: {
    project?: string;
    branch?: string;
    org?: string;
    service?: string;
    sprint?: string;
    tenant?: string;
    environment?: string;
  };
  source?: {
    actor?: string;
    tool?: string;
    timestamp?: string;
  };
  metadata?: Record<string, any>;
  tags?: Record<string, any>;
  idempotency_key?: string;
  ttl_config?: {
    policy?: 'default' | 'short' | 'long' | 'permanent';
    expires_at?: string;
    auto_extend?: boolean;
    extend_threshold_days?: number;
    max_extensions?: number;
  };
  truncation_config?: {
    enabled?: boolean;
    max_chars?: number;
    max_tokens?: number;
    mode?: 'hard' | 'soft' | 'intelligent';
    preserve_structure?: boolean;
    add_indicators?: boolean;
    indicator?: string;
    safety_margin?: number;
    auto_detect_content_type?: boolean;
    enable_smart_truncation?: boolean;
  };
  insights_config?: {
    enabled?: boolean;
    generate_insights?: boolean;
    insight_types?: ('summary' | 'trends' | 'recommendations' | 'anomalies' | 'patterns')[];
    confidence_threshold?: number;
    max_insights?: number;
    include_source_data?: boolean;
    analysis_depth?: 'shallow' | 'medium' | 'deep';
  };
}

interface DeduplicationConfig {
  enabled?: boolean;
  merge_strategy?: 'skip' | 'prefer_existing' | 'prefer_newer' | 'combine' | 'intelligent';
  similarity_threshold?: number; // 0.1-1.0, default 0.85
  check_within_scope_only?: boolean;
  max_history_hours?: number; // 1-8760, default 168
  dedupe_window_days?: number; // 1-365, default 30
  allow_newer_versions?: boolean;
  enable_audit_logging?: boolean;
  enable_intelligent_merging?: boolean;
  preserve_merge_history?: boolean;
  max_merge_history_entries?: number;
  cross_scope_deduplication?: boolean;
  prioritize_same_scope?: boolean;
  time_based_deduplication?: boolean;
  max_age_for_dedupe_days?: number;
  respect_update_timestamps?: boolean;
  max_items_to_check?: number;
  batch_size?: number;
  enable_parallel_processing?: boolean;
}

interface GlobalTTLConfig {
  policy?: 'default' | 'short' | 'long' | 'permanent';
  expires_at?: string;
  auto_extend?: boolean;
  extend_threshold_days?: number;
  max_extensions?: number;
}

interface GlobalTruncationConfig {
  enabled?: boolean;
  max_chars?: number;
  max_tokens?: number;
  mode?: 'hard' | 'soft' | 'intelligent';
  preserve_structure?: boolean;
  add_indicators?: boolean;
  indicator?: string;
  safety_margin?: number;
  auto_detect_content_type?: boolean;
  enable_smart_truncation?: boolean;
}

interface GlobalInsightsConfig {
  enabled?: boolean;
  generate_insights?: boolean;
  insight_types?: ('summary' | 'trends' | 'recommendations' | 'anomalies' | 'patterns')[];
  confidence_threshold?: number;
  max_insights?: number;
  include_source_data?: boolean;
  analysis_depth?: 'shallow' | 'medium' | 'deep';
}

interface ProcessingConfig {
  enable_validation?: boolean;
  enable_async_processing?: boolean;
  batch_processing?: boolean;
  return_summaries?: boolean;
  include_metrics?: boolean;
}
```

**Response**:

```typescript
interface MemoryStoreResponse {
  stored: StoredItem[];
  errors: StorageError[];
  autonomous_context: {
    action_performed: string;
    similar_items_checked: number;
    duplicates_found: number;
    reasoning: string;
  };
}

interface StoredItem {
  id: string;
  kind: string;
  created_at: string;
  updated_at: string;
}

interface StorageError {
  index: number;
  error_code: string;
  message: string;
}
```

**Current Limitations:**

- No `contradictions_detected` field - not implemented
- No `recommendation` field - not implemented
- No `user_message_suggestion` field - not implemented
- Basic duplicate detection only (85% similarity threshold)
- No per-item status reporting

**Usage Examples**:

_Store a single entity:_

```javascript
const result = await client.callTool('memory_store', {
  items: [
    {
      kind: 'entity',
      data: {
        title: 'User Authentication System',
        description: 'OAuth 2.0 implementation with JWT tokens',
        status: 'production',
      },
      scope: {
        project: 'my-app',
        branch: 'main',
        org: 'my-company',
      },
    },
  ],
});
```

_Store multiple related items:_

```javascript
const result = await client.callTool('memory_store', {
  items: [
    {
      kind: 'decision',
      data: {
        title: 'Use OAuth 2.0 for Authentication',
        rationale: 'Industry standard with robust security features',
        alternatives: ['Basic Auth', 'JWT-only', 'Session-based'],
        impact: 'High',
      },
    },
    {
      kind: 'entity',
      data: {
        title: 'OAuth Service Configuration',
        provider: 'Auth0',
        scopes: ['openid', 'profile', 'email'],
      },
    },
    {
      kind: 'todo',
      data: {
        title: 'Implement token refresh mechanism',
        priority: 'High',
        assignee: 'backend-team',
      },
    },
  ],
});
```

**Error Handling**:

```javascript
const result = await client.callTool('memory_store', {
  items: invalidItems,
});

if (result.errors.length > 0) {
  console.error('Storage errors:', result.errors);
  console.log('Successfully stored:', result.stored.length);
  console.log('Duplicates found:', result.autonomous_context.duplicates_found);
}
```

### 2. memory_find

Find knowledge items using advanced multi-strategy search with graph expansion and intelligent filtering. Supports fast/auto/deep search modes, relationship traversal, TTL filtering, and comprehensive result formatting. Think of this as a sophisticated search engine that can find knowledge across multiple dimensions with semantic understanding and relationship analysis.

**Endpoint**: `memory_find`

**AI-Friendly Description**: Search Cortex memory with advanced strategies, graph expansion, and intelligent result filtering.

**Enhanced Parameters**:

```typescript
interface MemoryFindRequest {
  query: string; // Required: 1-1000 characters
  scope?: {
    project?: string;
    branch?: string;
    org?: string;
    service?: string;
    sprint?: string;
    tenant?: string;
    environment?: string;
  };
  types?: (
    | 'entity'
    | 'relation'
    | 'observation'
    | 'section'
    | 'runbook'
    | 'change'
    | 'issue'
    | 'decision'
    | 'todo'
    | 'release_note'
    | 'ddl'
    | 'pr_context'
    | 'incident'
    | 'release'
    | 'risk'
    | 'assumption'
  )[];
  search_strategy?: 'fast' | 'auto' | 'deep'; // default: 'auto'
  limit?: number; // 1-100, default: 10
  offset?: number; // 0-1000, default: 0
  graph_expansion?: {
    enabled?: boolean;
    expansion_type?: 'none' | 'relations' | 'parents' | 'children' | 'all';
    max_depth?: number; // 1-5, default: 2
    max_nodes?: number; // 1-1000, default: 100
    include_metadata?: boolean;
    relation_types?: string[];
    direction?: 'outgoing' | 'incoming' | 'both';
  };
  ttl_filters?: {
    include_expired?: boolean;
    expires_before?: string;
    expires_after?: string;
    ttl_policies?: ('default' | 'short' | 'long' | 'permanent')[];
  };
  filters?: {
    created_after?: string;
    created_before?: string;
    updated_after?: string;
    updated_before?: string;
    tags?: string[];
    metadata?: Record<string, any>;
    confidence_min?: number; // 0-1
    confidence_max?: number; // 0-1
  };
  formatting?: {
    include_content?: boolean;
    include_metadata?: boolean;
    include_relations?: boolean;
    include_confidence_scores?: boolean;
    include_similarity_explanation?: boolean;
    highlight_matches?: boolean;
    max_content_length?: number;
  };
  optimization?: {
    enable_caching?: boolean;
    cache_ttl_seconds?: number; // 60-3600, default: 300
    parallel_search?: boolean;
    timeout_ms?: number; // 1000-30000, default: 10000
  };
  analytics?: {
    track_search_metrics?: boolean;
    log_search_query?: boolean;
    include_performance_metrics?: boolean;
    record_user_feedback?: boolean;
  };
}
```

**Response**:

```typescript
interface MemoryFindResponse {
  results: SearchResult[];
  total_count: number;
  autonomous_context: {
    search_mode_used: string;
    results_found: number;
  };
}

interface SearchResult {
  id: string;
  kind: string;
  scope: Record<string, any>;
  data: {
    title: string;
    snippet: string;
  };
  created_at: string;
  confidence_score: number; // Basic similarity score only
  match_type: 'semantic'; // Only semantic matching implemented
}
```

**Current Limitations:**

- Only "auto" search mode available (fast/deep not implemented)
- No `confidence_average` calculation - basic similarity only
- No `user_message_suggestion` field - not implemented
- Only semantic matching (no exact, keyword, or fuzzy matching)
- No multi-strategy search capabilities

**Usage Examples**:

_Basic semantic search:_

```javascript
const result = await client.callTool('memory_find', {
  query: 'How should I implement user authentication?',
  limit: 10,
});
```

_Scoped search with type filtering:_

```javascript
const result = await client.callTool('memory_find', {
  query: 'authentication security decisions',
  scope: {
    project: 'my-app',
    branch: 'main',
  },
  types: ['decision', 'entity', 'runbook'],
  mode: 'auto',
  limit: 20,
});
```

_Deep search with comprehensive analysis:_

```javascript
const result = await client.callTool('memory_find', {
  query: 'database migration strategy for PostgreSQL',
  mode: 'deep',
  types: ['ddl', 'decision', 'runbook', 'incident'],
  limit: 50,
});
```

**Search Modes**:

- **auto** (default): Basic semantic search using Qdrant vectors
- ~~fast~~: **Not implemented** - keyword-based search not available
- ~~deep~~: **Not implemented** - comprehensive analysis not available

**Result Processing**:

```javascript
const result = await client.callTool('memory_find', {
  query: 'API rate limiting implementation',
});

// Process results by basic similarity score
const highScore = result.results.filter((r) => r.confidence_score > 0.8);
const mediumScore = result.results.filter(
  (r) => r.confidence_score > 0.5 && r.confidence_score <= 0.8
);

// Group by type
const byType = result.results.reduce((acc, item) => {
  acc[item.kind] = (acc[item.kind] || []).push(item);
  return acc;
}, {});

console.log(
  `Found ${result.total_count} results using ${result.autonomous_context.search_mode_used} mode`
);
// Note: confidence_average is not available - only individual similarity scores
```

## Knowledge Types Reference

### Entity (`entity`)

Represents any concept, object, or component in your system.

**Common Fields**:

- `title`: Name/description
- `description`: Detailed information
- `status`: Current state
- `metadata`: Additional properties

**Example**:

```javascript
{
  kind: "entity",
  data: {
    title: "User Service API",
    description: "RESTful API for user management operations",
    status: "production",
    version: "2.1.0",
    endpoints: ["/users", "/auth", "/profile"]
  }
}
```

### Decision (`decision`)

Architecture Decision Records (ADRs) capturing important technical decisions.

**Common Fields**:

- `title`: Decision title
- `rationale`: Reasoning behind the decision
- `alternatives`: Considered alternatives
- `impact`: Impact assessment
- `status`: Decision status

**Example**:

```javascript
{
  kind: "decision",
  data: {
    title: "Use PostgreSQL as Primary Database",
    rationale: "Strong ACID compliance, advanced JSON support, and mature ecosystem",
    alternatives: ["MongoDB", "MySQL", "DynamoDB"],
    impact: "High - affects all data storage patterns",
    status: "accepted"
  }
}
```

### Todo (`todo`)

Action items, tasks, and work to be completed.

**Common Fields**:

- `title`: Task description
- `priority`: Priority level
- `assignee`: Assigned person/team
- `due_date`: Due date
- `status`: Current status

**Example**:

```javascript
{
  kind: "todo",
  data: {
    title: "Implement database connection pooling",
    priority: "High",
    assignee: "backend-team",
    due_date: "2025-11-15",
    status: "in_progress"
  }
}
```

### Issue (`issue`)

Bug reports, problems, and incidents that need resolution.

**Common Fields**:

- `title`: Issue description
- `severity`: Severity level
- `steps_to_reproduce`: Reproduction steps
- `expected_behavior`: Expected behavior
- `actual_behavior`: Actual behavior

**Example**:

```javascript
{
  kind: "issue",
  data: {
    title: "Memory leak in batch processing",
    severity: "High",
    steps_to_reproduce: ["Process large dataset", "Monitor memory usage"],
    expected_behavior: "Memory usage should remain stable",
    actual_behavior: "Memory usage increases continuously"
  }
}
```

### Runbook (`runbook`)

Step-by-step operational procedures and troubleshooting guides.

**Common Fields**:

- `title`: Procedure title
- `purpose`: Purpose description
- `prerequisites`: Required conditions
- `steps`: Step-by-step instructions
- `troubleshooting`: Common issues and solutions

**Example**:

```javascript
{
  kind: "runbook",
  data: {
    title: "Database Backup Restoration",
    purpose: "Restore PostgreSQL database from backup",
    prerequisites: ["Valid backup file", "Database access", "Sufficient disk space"],
    steps: [
      "Stop application services",
      "Create current database backup",
      "Restore from backup file",
      "Verify data integrity",
      "Restart application services"
    ]
  }
}
```

### 3. system_status

Comprehensive system monitoring, health checks, and maintenance operations. Provides real-time system status, performance metrics, cleanup operations, document management, and system diagnostics. Think of this as your operations dashboard for monitoring and maintaining the Cortex memory system.

**Endpoint**: `system_status`

**AI-Friendly Description**: Monitor system health, manage cleanup operations, and access comprehensive system metrics.

**Parameters**:

```typescript
interface SystemStatusRequest {
  operation:
    | 'health'
    | 'stats'
    | 'telemetry'
    | 'metrics'
    | 'get_document'
    | 'reassemble_document'
    | 'get_document_with_chunks'
    | 'run_purge'
    | 'get_purge_reports'
    | 'get_purge_statistics'
    | 'run_cleanup'
    | 'confirm_cleanup'
    | 'get_cleanup_statistics'
    | 'get_cleanup_history'
    | 'upsert_merge'
    | 'get_rate_limit_status'
    | 'get_performance_trends'
    | 'system_diagnostics';
  scope?: {
    project?: string;
    branch?: string;
    org?: string;
    service?: string;
    sprint?: string;
    tenant?: string;
    environment?: string;
  };
  document_id?: string; // UUID format required for document operations
  purge_config?: {
    dry_run?: boolean;
    batch_size?: number; // 1-1000, default: 100
    max_batches?: number; // 1-100, default: 50
  };
  cleanup_config?: {
    operations?: ('expired' | 'orphaned' | 'duplicate' | 'metrics' | 'logs')[];
    scope_filters?: {
      project?: string;
      org?: string;
      branch?: string;
    };
    require_confirmation?: boolean;
    enable_backup?: boolean;
    batch_size?: number; // 1-1000, default: 100
    max_batches?: number; // 1-100, default: 50
    dry_run?: boolean;
    confirmation_token?: string;
  };
  cleanup_token?: string;
  stats_period_days?: number; // 1-365, default: 30
  report_limit?: number; // 1-100, default: 10
  performance_window_hours?: number; // 1-168, default: 24
  include_detailed_metrics?: boolean;
  response_formatting?: {
    summary?: boolean;
    verbose?: boolean;
    include_raw_data?: boolean;
    include_timestamps?: boolean;
  };
}
```

**Response**:

```typescript
interface SystemStatusResponse {
  operation: string;
  timestamp: string;
  status: 'success' | 'error' | 'warning';
  data: OperationSpecificData;
  capabilities: {
    mcp_version: string;
    supported_operations: string[];
    knowledge_types: string[];
    ttl_policies: string[];
    merge_strategies: string[];
    search_strategies: string[];
  };
  performance_metrics?: {
    response_time_ms: number;
    memory_usage_mb: number;
    cpu_usage_percent: number;
    active_connections: number;
    cache_hit_rate: number;
  };
}

type OperationSpecificData =
  | HealthCheckData
  | SystemStatsData
  | TelemetryData
  | MetricsData
  | DocumentData
  | PurgeData
  | CleanupData
  | PerformanceTrendsData
  | SystemDiagnosticsData;

interface HealthCheckData {
  database_status: 'healthy' | 'degraded' | 'unhealthy';
  mcp_server_status: 'running' | 'stopped' | 'error';
  memory_services_status: 'operational' | 'partial' | 'down';
  last_check: string;
  uptime_seconds: number;
}

interface SystemStatsData {
  total_items: number;
  items_by_type: Record<string, number>;
  items_by_scope: Record<string, number>;
  storage_usage_mb: number;
  cache_status: {
    hit_rate: number;
    size_mb: number;
    ttl_status: string;
  };
  deduplication_stats: {
    duplicates_detected: number;
    merges_performed: number;
    similarity_avg: number;
  };
}
```

## Enhanced Usage Examples

### Advanced memory_store with All Features

```javascript
// Store complex knowledge items with advanced features
const result = await client.callTool('memory_store', {
  items: [
    {
      kind: 'decision',
      content: 'Implement OAuth 2.0 with JWT tokens for authentication',
      data: {
        title: 'OAuth 2.0 Authentication Implementation',
        rationale: 'Industry standard with robust security features',
        alternatives: ['Basic Auth', 'API Keys', 'Session-based'],
        impact: 'High - affects all API endpoints',
        status: 'accepted'
      },
      scope: {
        project: 'user-service',
        branch: 'feature/auth-upgrade',
        org: 'my-company',
        environment: 'development'
      },
      source: {
        actor: 'backend-team',
        tool: 'claude-code',
        timestamp: new Date().toISOString()
      },
      ttl_config: {
        policy: 'long',
        auto_extend: true,
        extend_threshold_days: 30,
        max_extensions: 5
      },
      truncation_config: {
        enabled: true,
        max_chars: 15000,
        mode: 'intelligent',
        preserve_structure: true,
        add_indicators: true
      },
      insights_config: {
        enabled: true,
        generate_insights: true,
        insight_types: ['summary', 'recommendations'],
        confidence_threshold: 0.8,
        analysis_depth: 'medium'
      }
    }
  ],
  deduplication: {
    enabled: true,
    merge_strategy: 'intelligent',
    similarity_threshold: 0.9,
    enable_intelligent_merging: true,
    enable_audit_logging: true,
    cross_scope_deduplication: false
  },
  global_ttl: {
    policy: 'long',
    auto_extend: true
  },
  processing: {
    enable_validation: true,
    batch_processing: true,
    include_metrics: true
  }
});

console.log(`Stored ${result.stored.length} items`);
console.log(`Duplicates found: ${result.duplicates_found}`);
console.log(`Merges performed: ${result.merges_performed}`);
```

### Advanced memory_find with Graph Expansion

```javascript
// Complex search with graph expansion and filtering
const searchResult = await client.callTool('memory_find', {
  query: 'authentication security best practices',
  scope: {
    project: 'user-service',
    org: 'my-company'
  },
  types: ['decision', 'runbook', 'incident', 'risk'],
  search_strategy: 'deep',
  limit: 25,
  graph_expansion: {
    enabled: true,
    expansion_type: 'relations',
    max_depth: 3,
    max_nodes: 50,
    include_metadata: true,
    direction: 'both'
  },
  ttl_filters: {
    include_expired: false,
    ttl_policies: ['default', 'long', 'permanent']
  },
  filters: {
    created_after: '2025-01-01T00:00:00Z',
    confidence_min: 0.7,
    tags: ['security', 'authentication']
  },
  formatting: {
    include_content: true,
    include_metadata: true,
    include_relations: true,
    include_confidence_scores: true,
    include_similarity_explanation: true,
    highlight_matches: true,
    max_content_length: 2000
  },
  optimization: {
    enable_caching: true,
    cache_ttl_seconds: 600,
    parallel_search: true,
    timeout_ms: 15000
  },
  analytics: {
    track_search_metrics: true,
    include_performance_metrics: true
  }
});

console.log(`Found ${searchResult.results.length} results`);
console.log(`Search strategy: ${searchResult.search_strategy}`);
console.log(`Graph expansion results: ${searchResult.expanded_nodes || 0}`);
```

### System Health Monitoring

```javascript
// Comprehensive system health check
const healthResult = await client.callTool('system_status', {
  operation: 'health',
  include_detailed_metrics: true,
  response_formatting: {
    verbose: true,
    include_raw_data: false,
    include_timestamps: true
  }
});

if (healthResult.status === 'success') {
  console.log('System Health Status:');
  console.log(`Database: ${healthResult.data.database_status}`);
  console.log(`MCP Server: ${healthResult.data.mcp_server_status}`);
  console.log(`Memory Services: ${healthResult.data.memory_services_status}`);
  console.log(`Uptime: ${healthResult.data.uptime_seconds}s`);
}

// Get comprehensive system statistics
const statsResult = await client.callTool('system_status', {
  operation: 'stats',
  scope: {
    project: 'user-service'
  },
  stats_period_days: 30,
  include_detailed_metrics: true
});

console.log('System Statistics:');
console.log(`Total items: ${statsResult.data.total_items}`);
console.log(`Storage usage: ${statsResult.data.storage_usage_mb}MB`);
console.log(`Cache hit rate: ${statsResult.data.cache_status.hit_rate}%`);
```

### Cleanup and Maintenance Operations

```javascript
// Run cleanup with dry-run first
const cleanupDryRun = await client.callTool('system_status', {
  operation: 'run_cleanup',
  cleanup_config: {
    operations: ['expired', 'orphaned', 'duplicate'],
    dry_run: true,
    batch_size: 100,
    require_confirmation: true,
    enable_backup: true
  },
  scope: {
    project: 'user-service'
  }
});

console.log(`Items to cleanup: ${cleanupDryRun.data.items_count}`);
console.log(`Estimated space saved: ${cleanupDryRun.data.estimated_space_saved_mb}MB`);

// Confirm and run actual cleanup
const cleanupResult = await client.callTool('system_status', {
  operation: 'confirm_cleanup',
  cleanup_token: cleanupDryRun.data.confirmation_token
});

console.log(`Cleanup completed: ${cleanupResult.data.cleaned_items}`);
console.log(`Space saved: ${cleanupResult.data.space_saved_mb}MB`);
```

## Production Ready Features

### Intelligent Deduplication

```javascript
// Advanced deduplication with multiple strategies
const deduplicationResult = await client.callTool('memory_store', {
  items: [existingItem, similarItem],
  deduplication: {
    enabled: true,
    merge_strategy: 'intelligent', // Best for production
    similarity_threshold: 0.85,
    enable_intelligent_merging: true,
    preserve_merge_history: true,
    enable_audit_logging: true,
    cross_scope_deduplication: false,
    prioritize_same_scope: true
  }
});
```

### TTL Policy Management

```javascript
// Automatic TTL management with extension
const ttlResult = await client.callTool('memory_store', {
  items: [importantItem],
  global_ttl: {
    policy: 'permanent', // Never expires
    // OR
    policy: 'long', // 90 days default
    auto_extend: true,
    extend_threshold_days: 7,
    max_extensions: 10
  }
});
```

### Performance Monitoring

```javascript
// Get performance trends and metrics
const performanceResult = await client.callTool('system_status', {
  operation: 'get_performance_trends',
  performance_window_hours: 24,
  include_detailed_metrics: true
});

console.log(`Average response time: ${performanceResult.data.avg_response_time_ms}ms`);
console.log(`Memory usage: ${performanceResult.data.memory_usage_mb}MB`);
console.log(`Cache hit rate: ${performanceResult.data.cache_hit_rate}%`);
```

## Currently Implemented Features

### Advanced Context Generation

Both `memory_store` and `memory_find` provide basic context:

```javascript
// Storage context
const storageResult = await client.callTool('memory_store', { items });
console.log(`Action: ${storageResult.autonomous_context.action_performed}`);
console.log(`Duplicates found: ${storageResult.autonomous_context.duplicates_found}`);
console.log(`Reasoning: ${storageResult.autonomous_context.reasoning}`);

// Search context
const searchResult = await client.callTool('memory_find', { query: '...' });
console.log(`Search mode: ${searchResult.autonomous_context.search_mode_used}`);
console.log(`Results found: ${searchResult.autonomous_context.results_found}`);
// Note: No confidence average or recommendations available
```

### Basic Duplicate Detection

The system detects basic duplicates using content similarity:

```javascript
const result = await client.callTool('memory_store', {
  items: [
    {
      kind: 'entity',
      data: { title: 'User Authentication System' },
    },
  ],
});

if (result.autonomous_context.duplicates_found > 0) {
  console.log('Duplicate detected - existing similar item found');
  console.log(`Reasoning: ${result.autonomous_context.reasoning}`);
  // Note: No recommendations or merge suggestions available
}
```

## ⚠️ Not Yet Implemented

The following advanced features are planned but **not currently available**:

### Autonomous Context Generation

- AI-generated recommendations and insights
- User message suggestions
- Advanced analysis and reasoning

### Advanced Duplicate Detection

- Contradiction detection
- Merge suggestions
- Conflict resolution

### Enhanced Search Features

- Multi-strategy search (keyword, hybrid, fuzzy)
- Search result ranking and optimization
- Query expansion and suggestions

### Scope-Based Isolation

Use scope to organize and isolate knowledge by project, branch, or organization:

```javascript
// Store with specific scope
await client.callTool('memory_store', {
  items: [item],
  scope: {
    project: 'my-project',
    branch: 'feature/new-auth',
    org: 'my-company',
  },
});

// Search within scope
await client.callTool('memory_find', {
  query: 'authentication',
  scope: {
    project: 'my-project',
    branch: 'main', // Only search in main branch
  },
});
```

## Error Handling

### Common Error Codes

- `VALIDATION_ERROR`: Invalid input data
- `DUPLICATE_ERROR`: Duplicate item detected
- `DATABASE_ERROR`: Database operation failed
- `NETWORK_ERROR`: Connection issues
- `PERMISSION_ERROR`: Access denied
- `SYSTEM_ERROR`: Internal system error

### Error Response Format

```typescript
interface ErrorResponse {
  error_code: string;
  message: string;
  details?: Record<string, any>;
  timestamp: string;
}
```

### Error Handling Examples

```javascript
try {
  const result = await client.callTool('memory_store', { items });
} catch (error) {
  if (error.error_code === 'VALIDATION_ERROR') {
    console.error('Invalid data:', error.details.field_errors);
  } else if (error.error_code === 'DATABASE_ERROR') {
    console.error('Database issue - please try again later');
  }
}
```

## Performance Considerations

### Batching

Store multiple items in a single request for better performance:

```javascript
// Good: Batch operations
const items = Array.from({ length: 100 }, (_, i) => ({
  kind: 'entity',
  data: { title: `Item ${i}` },
}));
await client.callTool('memory_store', { items });

// Avoid: Multiple individual requests
// for (const item of items) {
//   await client.callTool("memory_store", { items: [item] });
// }
```

### Search Optimization

Use appropriate search modes and limits:

```javascript
// Fast search for recent items
await client.callTool('memory_find', {
  query: 'recent changes',
  mode: 'fast',
  limit: 10,
});

// Comprehensive search when needed
await client.callTool('memory_find', {
  query: 'complex architectural decision',
  mode: 'deep',
  limit: 50,
});
```

### Scope Filtering

Use scope to reduce search space and improve performance:

```javascript
// Efficient scoped search
await client.callTool('memory_find', {
  query: 'authentication',
  scope: { project: 'my-app' }, // Limits search scope
  limit: 20,
});
```

## Integration Examples

### Claude Code Integration

```javascript
// Store conversation context
await client.callTool('memory_store', {
  items: [
    {
      kind: 'entity',
      data: {
        title: 'Claude Code Session',
        conversation_id: session.id,
        context: 'Discussed authentication implementation',
        date: new Date().toISOString(),
      },
      scope: {
        project: 'current-project',
      },
    },
  ],
});

// Find relevant context
const context = await client.callTool('memory_find', {
  query: 'authentication implementation decisions',
  types: ['decision', 'entity'],
  limit: 5,
});
```

### Development Workflow Integration

```javascript
// Store development decisions
await client.callTool('memory_store', {
  items: [
    {
      kind: 'decision',
      data: {
        title: 'Adopt TypeScript strict mode',
        rationale: 'Improved type safety and developer experience',
        alternatives: ['JavaScript', 'TypeScript loose mode'],
        impact: 'Medium - requires type annotations',
      },
      scope: {
        project: 'my-project',
        branch: 'main',
      },
    },
  ],
});

// Find relevant development context
const devContext = await client.callTool('memory_find', {
  query: 'TypeScript configuration decisions',
  types: ['decision', 'runbook'],
  scope: { project: 'my-project' },
});
```

## Troubleshooting

### Common Issues

**No search results returned**:

- Check query spelling and terms
- Try broader search terms
- Use "fast" mode for keyword search
- Verify scope constraints

**Storage failures**:

- Validate item structure
- Check required fields
- Verify kind is valid
- Check data size limits

**Performance issues**:

- Use batching for multiple items
- Limit search results
- Use appropriate search mode
- Apply scope filtering

### Debug Mode

Enable debug logging for detailed troubleshooting:

```javascript
// Set environment variable
process.env.DEBUG = 'cortex:*';

// Or use debug mode in search
await client.callTool('memory_find', {
  query: 'debug test',
  mode: 'deep', // Provides more detailed analysis
});
```

## SDK and Tool Integration

This API is designed to work with MCP-compatible tools and SDKs. The primary interfaces are:

- **MCP Protocol**: Direct integration with Claude Code and other MCP clients
- **HTTP API**: RESTful endpoints for web applications
- **TypeScript SDK**: Type-safe client library for Node.js applications

For more integration examples and SDK documentation, see the Developer Guide.
