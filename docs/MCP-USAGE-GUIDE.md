# MCP Cortex Usage Guide & Best Practices

## Overview

This comprehensive guide covers the effective use of the Cortex Memory MCP Server v2.0 through the Model Context Protocol (MCP). It includes practical examples, best practices, performance optimization techniques, and common patterns for AI agent integration.

**🚀 Quick Start**: If you're new to MCP Cortex, start with the [Quick Start Guide](SETUP-QUICK-START.md) and then return here for advanced usage patterns.

## Table of Contents

1. [Getting Started with MCP Cortex](#getting-started-with-mcp-cortex)
2. [Core MCP Tool Usage](#core-mcp-tool-usage)
3. [Knowledge Type Best Practices](#knowledge-type-best-practices)
4. [Advanced Features](#advanced-features)
5. [Performance Optimization](#performance-optimization)
6. [Error Handling and Resilience](#error-handling-and-resilience)
7. [Integration Patterns](#integration-patterns)
8. [Monitoring and Maintenance](#monitoring-and-maintenance)
9. [Common Pitfalls and Solutions](#common-pitfalls-and-solutions)

---

## Getting Started with MCP Cortex

### Basic MCP Configuration

```toml
# claude_desktop_config.json
{
  "mcpServers": {
    "cortex": {
      "command": "cortex",
      "args": [],
      "env": {
        "OPENAI_API_KEY": "your-api-key-here",
        "QDRANT_URL": "http://localhost:6333"
      }
    }
  }
}
```

**⚠️ Important**: Only ONE Cortex configuration is allowed per MCP setup.

### Basic Usage Pattern

```javascript
// Store knowledge
const storeResult = await call_tool('memory_store', {
  items: [
    {
      kind: 'entity',
      data: { title: 'User Preferences', theme: 'dark' },
      scope: { project: 'user-profile' },
    },
  ],
});

// Search knowledge
const searchResult = await call_tool('memory_find', {
  query: 'user preferences',
  limit: 10,
});

// System status
const healthResult = await call_tool('system_status', {
  operation: 'health',
});
```

---

## Core MCP Tool Usage

### 1. memory_store - Intelligent Knowledge Storage

#### Basic Usage

```javascript
// Simple entity storage
await call_tool('memory_store', {
  items: [
    {
      kind: 'entity',
      data: {
        title: 'User Service API',
        description: 'RESTful API for user management',
        version: '2.1.0',
      },
      scope: {
        project: 'user-service',
        branch: 'main',
      },
    },
  ],
});
```

#### Advanced Usage with All Features

```javascript
// Comprehensive knowledge storage with advanced features
await call_tool('memory_store', {
  items: [
    {
      kind: 'decision',
      content: 'Implement OAuth 2.0 with JWT tokens for authentication',
      data: {
        title: 'OAuth 2.0 Authentication Implementation',
        rationale: 'Industry standard with robust security features',
        alternatives: ['Basic Auth', 'API Keys', 'Session-based'],
        impact: 'High - affects all API endpoints',
        status: 'accepted',
        decision_date: '2025-01-15',
        decision_maker: 'architecture-team',
      },
      scope: {
        project: 'user-service',
        branch: 'feature/auth-upgrade',
        org: 'my-company',
        environment: 'development',
      },
      source: {
        actor: 'backend-team',
        tool: 'claude-code',
        timestamp: '2025-01-15T10:30:00Z',
      },
      ttl_config: {
        policy: 'long',
        auto_extend: true,
        extend_threshold_days: 30,
        max_extensions: 5,
      },
      truncation_config: {
        enabled: true,
        max_chars: 15000,
        mode: 'intelligent',
        preserve_structure: true,
        add_indicators: true,
      },
      insights_config: {
        enabled: true,
        generate_insights: true,
        insight_types: ['summary', 'recommendations'],
        confidence_threshold: 0.8,
        analysis_depth: 'medium',
      },
    },
  ],
  deduplication: {
    enabled: true,
    merge_strategy: 'intelligent',
    similarity_threshold: 0.9,
    enable_intelligent_merging: true,
    enable_audit_logging: true,
    cross_scope_deduplication: false,
    prioritize_same_scope: true,
  },
  global_ttl: {
    policy: 'long',
    auto_extend: true,
  },
  processing: {
    enable_validation: true,
    batch_processing: true,
    include_metrics: true,
  },
});
```

#### Batch Operations

```javascript
// Store multiple items efficiently
const knowledgeItems = [
  {
    kind: 'entity',
    data: { title: 'Database Service', status: 'production' },
    scope: { project: 'infrastructure' },
  },
  {
    kind: 'decision',
    data: { title: 'Use PostgreSQL', rationale: 'ACID compliance' },
    scope: { project: 'infrastructure' },
  },
  {
    kind: 'todo',
    data: { title: 'Setup monitoring', priority: 'high' },
    scope: { project: 'infrastructure' },
  },
];

const result = await call_tool('memory_store', {
  items: knowledgeItems,
  deduplication: {
    enabled: true,
    merge_strategy: 'intelligent',
    similarity_threshold: 0.85,
  },
});

console.log(`Stored: ${result.stored.length}, Duplicates: ${result.duplicates_found}`);
```

### 2. memory_find - Advanced Search Capabilities

#### Basic Search

```javascript
// Simple semantic search
await call_tool('memory_find', {
  query: 'database configuration',
  limit: 10,
});
```

#### Advanced Search with All Features

```javascript
// Comprehensive search with all advanced features
await call_tool('memory_find', {
  query: 'authentication security best practices',
  scope: {
    project: 'security-audit',
    org: 'my-company',
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
    direction: 'both',
  },
  ttl_filters: {
    include_expired: false,
    ttl_policies: ['default', 'long', 'permanent'],
  },
  filters: {
    created_after: '2025-01-01T00:00:00Z',
    confidence_min: 0.7,
    tags: ['security', 'authentication'],
  },
  formatting: {
    include_content: true,
    include_metadata: true,
    include_relations: true,
    include_confidence_scores: true,
    include_similarity_explanation: true,
    highlight_matches: true,
    max_content_length: 2000,
  },
  optimization: {
    enable_caching: true,
    cache_ttl_seconds: 600,
    parallel_search: true,
    timeout_ms: 15000,
  },
  analytics: {
    track_search_metrics: true,
    include_performance_metrics: true,
  },
});
```

#### Search Strategies

```javascript
// Fast search for quick results
await call_tool('memory_find', {
  query: 'recent changes',
  search_strategy: 'fast',
  limit: 5,
});

// Auto search (default) - balanced approach
await call_tool('memory_find', {
  query: 'api documentation',
  search_strategy: 'auto',
  limit: 15,
});

// Deep search for comprehensive analysis
await call_tool('memory_find', {
  query: 'comprehensive security audit',
  search_strategy: 'deep',
  limit: 50,
  graph_expansion: {
    enabled: true,
    max_depth: 4,
  },
});
```

### 3. system_status - Monitoring and Maintenance

#### Health Checks

```javascript
// Basic health check
const health = await call_tool('system_status', {
  operation: 'health',
  include_detailed_metrics: true,
  response_formatting: {
    verbose: true,
    include_timestamps: true,
  },
});

if (health.status === 'success') {
  console.log('✅ System healthy');
  console.log(`Database: ${health.data.database_status}`);
  console.log(`Uptime: ${health.data.uptime_seconds}s`);
}
```

#### System Statistics

```javascript
// Get comprehensive system statistics
const stats = await call_tool('system_status', {
  operation: 'stats',
  scope: { project: 'user-service' },
  stats_period_days: 30,
  include_detailed_metrics: true,
});

console.log(`Total items: ${stats.data.total_items}`);
console.log(`Storage usage: ${stats.data.storage_usage_mb}MB`);
console.log(`Cache hit rate: ${stats.data.cache_status.hit_rate}%`);
```

#### Maintenance Operations

```javascript
// Run cleanup with dry-run first
const cleanupDryRun = await call_tool('system_status', {
  operation: 'run_cleanup',
  cleanup_config: {
    operations: ['expired', 'orphaned', 'duplicate'],
    dry_run: true,
    batch_size: 100,
    require_confirmation: true,
    enable_backup: true,
  },
  scope: { project: 'user-service' },
});

console.log(`Items to cleanup: ${cleanupDryRun.data.items_count}`);

// Confirm and run actual cleanup
if (cleanupDryRun.data.confirmation_token) {
  const cleanupResult = await call_tool('system_status', {
    operation: 'confirm_cleanup',
    cleanup_token: cleanupDryRun.data.confirmation_token,
  });

  console.log(`Cleanup completed: ${cleanupResult.data.cleaned_items} items`);
}
```

---

## Knowledge Type Best Practices

### Entity Knowledge Type

**Use for**: Representing concepts, objects, components, or any discrete item.

```javascript
// Good entity example
await call_tool('memory_store', {
  items: [
    {
      kind: 'entity',
      data: {
        entity_type: 'user',
        name: 'john_doe',
        data: {
          email: 'john@example.com',
          role: 'senior_developer',
          department: 'engineering',
          skills: ['TypeScript', 'Node.js', 'PostgreSQL'],
          join_date: '2023-01-15',
        },
      },
      scope: { project: 'hr-system', branch: 'main' },
    },
  ],
});
```

**Best Practices**:

- Use descriptive `entity_type` values
- Include essential metadata in the `data` field
- Use consistent naming conventions
- Store related entities in the same scope

### Decision Knowledge Type

**Use for**: Architecture Decision Records (ADRs), technical decisions, important choices.

```javascript
// Good decision example
await call_tool('memory_store', {
  items: [
    {
      kind: 'decision',
      data: {
        title: 'Adopt TypeScript for Frontend Development',
        rationale: 'Type safety improves developer experience and reduces runtime errors',
        alternatives: [
          {
            option: 'JavaScript',
            pros: ['Faster development', 'No compilation step'],
            cons: ['No type safety', 'Runtime errors'],
          },
          {
            option: 'Flow',
            pros: ['Gradual typing', 'Facebook support'],
            cons: ['Smaller ecosystem', 'Learning curve'],
          },
        ],
        decision: 'TypeScript',
        impact: {
          level: 'high',
          affected_components: ['frontend-build', 'developer-training'],
          migration_effort: 'medium',
        },
        status: 'accepted',
        decision_date: '2025-01-15',
        decision_maker: 'tech-leads',
        next_review_date: '2025-07-15',
      },
      scope: { project: 'frontend-platform', branch: 'main' },
    },
  ],
});
```

**Best Practices**:

- Always include alternatives with pros/cons
- Document the impact level clearly
- Include decision makers and dates
- Set review dates for important decisions
- Link to related decisions or issues

### Todo Knowledge Type

**Use for**: Action items, tasks, work to be completed, deliverables.

```javascript
// Good todo example
await call_tool('memory_store', {
  items: [
    {
      kind: 'todo',
      data: {
        title: 'Implement API rate limiting',
        description: 'Add rate limiting to prevent API abuse and ensure fair usage',
        priority: 'high',
        status: 'in_progress',
        assignee: 'backend-team',
        due_date: '2025-02-01',
        estimated_hours: 16,
        tags: ['security', 'api', 'infrastructure'],
        subtasks: [
          'Research rate limiting libraries',
          'Design rate limiting strategy',
          'Implement middleware',
          'Add monitoring and alerts',
          'Write documentation',
          'Update API tests',
        ],
        dependencies: ['api-authentication-completed'],
        definition_of_done: [
          'Rate limiting implemented for all endpoints',
          'Monitoring dashboards updated',
          'Documentation completed',
          'Tests pass with >95% coverage',
        ],
      },
      scope: { project: 'api-platform', branch: 'feature/rate-limiting' },
    },
  ],
});
```

**Best Practices**:

- Use clear, actionable titles
- Include realistic time estimates
- Break down large tasks into subtasks
- Define clear "definition of done" criteria
- Track dependencies between tasks
- Update status regularly

### Incident Knowledge Type

**Use for**: System incidents, outages, security events, operational issues.

```javascript
// Good incident example
await call_tool('memory_store', {
  items: [
    {
      kind: 'incident',
      data: {
        incident_id: 'INC-2025-042',
        title: 'Database Connection Pool Exhaustion',
        severity: 'high',
        priority: 'P0',
        status: 'resolved',
        category: 'infrastructure',
        impact: {
          affected_services: ['user-api', 'order-service', 'notification-service'],
          user_impact: 'high',
          business_impact: 'revenue_loss',
          estimated_affected_users: 50000,
          downtime_duration_minutes: 45,
        },
        timeline: {
          detected_at: '2025-01-15T09:15:00Z',
          acknowledged_at: '2025-01-15T09:20:00Z',
          mitigated_at: '2025-01-15T09:45:00Z',
          resolved_at: '2025-01-15T10:00:00Z',
        },
        root_cause: {
          primary: 'Database connection pool not properly configured for high traffic',
          contributing: ['Insufficient monitoring', 'Missing alert thresholds'],
        },
        resolution: {
          description: 'Increased connection pool size and added proper monitoring',
          permanent_fix: 'Updated configuration and added alerting',
          preventive_measures: ['Add load testing', 'Implement circuit breakers'],
        },
        lessons_learned: [
          'Need better capacity planning',
          'Monitoring gaps identified',
          'Response time can be improved',
        ],
        postmortem_required: true,
        postmortem_completed: true,
      },
      scope: { project: 'incident-management', branch: 'main' },
    },
  ],
});
```

**Best Practices**:

- Use consistent incident ID format
- Document full timeline with timestamps
- Clearly identify root causes and contributing factors
- Include preventive measures
- Complete postmortem documentation
- Track lessons learned for future prevention

---

## Advanced Features

### Intelligent Deduplication

```javascript
// Configure intelligent deduplication
await call_tool('memory_store', {
  items: [knowledgeItem],
  deduplication: {
    enabled: true,
    merge_strategy: 'intelligent', // Best for most use cases
    similarity_threshold: 0.85, // Adjust based on needs
    enable_intelligent_merging: true,
    enable_audit_logging: true,
    preserve_merge_history: false,
    cross_scope_deduplication: false, // Keep scope isolation
    prioritize_same_scope: true,
    time_based_deduplication: true,
    max_age_for_dedupe_days: 90,
  },
});
```

**Merge Strategies**:

- `skip`: Don't store duplicates
- `prefer_existing`: Keep existing item
- `prefer_newer`: Keep newer item
- `combine`: Merge both items
- `intelligent`: AI-powered merging (recommended)

### TTL Policy Management

```javascript
// Configure TTL policies for different content types
const shortLivedItem = {
  kind: 'observation',
  data: { content: 'Temporary user session data' },
  ttl_config: {
    policy: 'short', // 1 day default
    auto_extend: false,
    expires_at: '2025-01-16T00:00:00Z',
  },
};

const longLivedItem = {
  kind: 'decision',
  data: { title: 'Architecture decision' },
  ttl_config: {
    policy: 'long', // 90 days default
    auto_extend: true,
    extend_threshold_days: 30,
    max_extensions: 5,
  },
};

const permanentItem = {
  kind: 'entity',
  data: { title: 'Core system component' },
  ttl_config: {
    policy: 'permanent', // Never expires
  },
};

await call_tool('memory_store', {
  items: [shortLivedItem, longLivedItem, permanentItem],
});
```

### Graph Expansion Search

```javascript
// Search with relationship expansion
await call_tool('memory_find', {
  query: 'authentication system',
  graph_expansion: {
    enabled: true,
    expansion_type: 'relations', // Explore related items
    max_depth: 3, // How deep to explore
    max_nodes: 50, // Maximum items to return
    include_metadata: true,
    direction: 'both', // Both incoming and outgoing
    relation_types: ['depends_on', 'relates_to', 'implements'],
  },
});
```

### Content Chunking

```javascript
// Store large content with intelligent chunking
await call_tool('memory_store', {
  items: [
    {
      kind: 'section',
      content: longDocumentContent, // > 10,000 characters
      data: {
        title: 'Comprehensive API Documentation',
        section_type: 'documentation',
      },
      truncation_config: {
        enabled: true,
        max_chars: 8000, // Chunk size
        mode: 'intelligent', // Smart chunking
        preserve_structure: true, // Keep sections intact
        add_indicators: true, // Add continuation markers
        safety_margin: 0.1, // 10% safety margin
      },
    },
  ],
});
```

---

## Performance Optimization

### Search Optimization

```javascript
// Optimized search for better performance
await call_tool('memory_find', {
  query: 'specific search terms',
  search_strategy: 'fast', // Use fast for quick results
  limit: 10, // Limit result set size
  scope: { project: 'specific' }, // Narrow search scope
  optimization: {
    enable_caching: true,
    cache_ttl_seconds: 300, // 5 minute cache
    parallel_search: false, // Disable for small searches
    timeout_ms: 5000, // Reasonable timeout
  },
});
```

### Batch Processing

```javascript
// Process large datasets efficiently
const largeDataset = Array.from({ length: 1000 }, (_, i) => ({
  kind: 'entity',
  data: { title: `Item ${i}` },
  scope: { project: 'batch-test' },
}));

// Process in batches
const batchSize = 50;
for (let i = 0; i < largeDataset.length; i += batchSize) {
  const batch = largeDataset.slice(i, i + batchSize);

  await call_tool('memory_store', {
    items: batch,
    processing: {
      batch_processing: true,
      enable_async_processing: false,
    },
  });

  // Small delay between batches
  await new Promise((resolve) => setTimeout(resolve, 100));
}
```

### Caching Strategy

```javascript
// Enable intelligent caching for frequent searches
await call_tool('memory_find', {
  query: 'frequently searched term',
  optimization: {
    enable_caching: true,
    cache_ttl_seconds: 3600, // 1 hour cache
    parallel_search: true,
  },
  analytics: {
    track_search_metrics: true,
    record_user_feedback: true, // Improve future searches
  },
});
```

---

## Error Handling and Resilience

### Robust Error Handling

```javascript
async function safeMemoryStore(items, retries = 3) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const result = await call_tool('memory_store', {
        items,
        processing: {
          enable_validation: true,
        },
      });

      if (result.errors.length > 0) {
        console.warn(`Attempt ${attempt}: ${result.errors.length} items failed`);
        // Retry only the failed items
        const failedItems = items.filter((_, index) =>
          result.errors.some((error) => error.index === index)
        );
        items = failedItems;
      } else {
        return result;
      }
    } catch (error) {
      console.error(`Attempt ${attempt} failed:`, error);
      if (attempt === retries) {
        throw error;
      }
      // Exponential backoff
      await new Promise((resolve) => setTimeout(resolve, Math.pow(2, attempt) * 1000));
    }
  }
}
```

### Rate Limiting Handling

```javascript
async function handleRateLimiting(operation, args) {
  try {
    return await call_tool(operation, args);
  } catch (error) {
    if (error.error === 'RATE_LIMIT_EXCEEDED') {
      const resetIn = error.rate_limit.reset_in_seconds;
      console.log(`Rate limited. Retrying in ${resetIn} seconds...`);

      // Wait for rate limit reset
      await new Promise((resolve) => setTimeout(resolve, resetIn * 1000));

      // Retry the operation
      return await call_tool(operation, args);
    }
    throw error;
  }
}
```

### Validation Before Storage

```javascript
function validateKnowledgeItem(item) {
  const requiredFields = {
    entity: ['entity_type', 'name'],
    decision: ['title', 'rationale'],
    todo: ['title', 'status'],
    incident: ['title', 'severity', 'status'],
  };

  const kind = item.kind;
  if (requiredFields[kind]) {
    for (const field of requiredFields[kind]) {
      if (!item.data[field]) {
        throw new Error(`Missing required field '${field}' for ${kind}`);
      }
    }
  }

  // Validate scope
  if (!item.scope || !item.scope.project) {
    throw new Error('Project scope is required');
  }

  return true;
}

// Usage
try {
  validateKnowledgeItem(knowledgeItem);
  const result = await call_tool('memory_store', {
    items: [knowledgeItem],
  });
} catch (error) {
  console.error('Validation failed:', error.message);
  // Handle validation error appropriately
}
```

---

## Integration Patterns

### Claude Code Integration

```javascript
// Session context management
async function storeConversationContext(sessionId, context) {
  await call_tool('memory_store', {
    items: [
      {
        kind: 'entity',
        data: {
          title: `Claude Code Session ${sessionId}`,
          conversation_context: context,
          session_id: sessionId,
          timestamp: new Date().toISOString(),
        },
        scope: {
          project: 'claude-sessions',
          branch: 'main',
        },
        ttl_config: {
          policy: 'short', // Sessions are temporary
          auto_extend: true,
          extend_threshold_days: 1,
        },
      },
    ],
  });
}

// Retrieve relevant context
async function getRelevantContext(query) {
  const result = await call_tool('memory_find', {
    query,
    types: ['entity', 'decision', 'todo'],
    limit: 5,
    search_strategy: 'auto',
    formatting: {
      include_content: true,
      include_metadata: true,
    },
  });

  return result.results.map((item) => ({
    content: item.content,
    metadata: item.metadata,
    confidence: item.confidence_score,
  }));
}
```

### Development Workflow Integration

```javascript
// Track development decisions
async function recordDecision(title, rationale, alternatives) {
  await call_tool('memory_store', {
    items: [
      {
        kind: 'decision',
        data: {
          title,
          rationale,
          alternatives,
          status: 'proposed',
          decision_date: new Date().toISOString(),
          decision_maker: 'development-team',
        },
        scope: {
          project: getCurrentProject(),
          branch: getCurrentBranch(),
        },
        source: {
          actor: 'developer',
          tool: 'ide-plugin',
          timestamp: new Date().toISOString(),
        },
      },
    ],
  });
}

// Find related decisions
async function findRelatedDecisions(currentContext) {
  return await call_tool('memory_find', {
    query: currentContext,
    types: ['decision'],
    scope: {
      project: getCurrentProject(),
    },
    graph_expansion: {
      enabled: true,
      expansion_type: 'relations',
      max_depth: 2,
    },
  });
}
```

### CI/CD Pipeline Integration

```javascript
// Record deployment information
async function recordDeployment(deploymentInfo) {
  await call_tool('memory_store', {
    items: [
      {
        kind: 'release',
        data: {
          version: deploymentInfo.version,
          release_type: deploymentInfo.type,
          environment: deploymentInfo.environment,
          deployed_at: new Date().toISOString(),
          features: deploymentInfo.features,
          fixes: deploymentInfo.fixes,
          deployment_info: {
            strategy: deploymentInfo.strategy,
            duration_minutes: deploymentInfo.duration,
            health_checks_passed: true,
          },
        },
        scope: {
          project: deploymentInfo.project,
          branch: deploymentInfo.branch,
        },
      },
    ],
  });
}

// Check deployment history
async function getDeploymentHistory(project, limit = 10) {
  return await call_tool('memory_find', {
    query: 'deployment',
    types: ['release'],
    scope: { project },
    filters: {
      created_after: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(), // Last 30 days
    },
    limit,
    formatting: {
      include_metadata: true,
      include_content: false,
    },
  });
}
```

---

## Monitoring and Maintenance

### Health Monitoring

```javascript
// Comprehensive health check
async function performHealthCheck() {
  const health = await call_tool('system_status', {
    operation: 'health',
    include_detailed_metrics: true,
  });

  if (health.status !== 'success') {
    console.error('❌ System unhealthy:', health);
    return false;
  }

  console.log('✅ System healthy');
  console.log(`Database: ${health.data.database_status}`);
  console.log(`MCP Server: ${health.data.mcp_server_status}`);
  console.log(`Uptime: ${health.data.uptime_seconds}s`);

  return true;
}

// Performance monitoring
async function monitorPerformance() {
  const trends = await call_tool('system_status', {
    operation: 'get_performance_trends',
    performance_window_hours: 24,
    include_detailed_metrics: true,
  });

  console.log('Performance Metrics (24h):');
  console.log(`Avg response time: ${trends.data.avg_response_time_ms}ms`);
  console.log(`Memory usage: ${trends.data.memory_usage_mb}MB`);
  console.log(`Cache hit rate: ${trends.data.cache_hit_rate}%`);

  // Alert if performance is degraded
  if (trends.data.avg_response_time_ms > 1000) {
    console.warn('⚠️ High response time detected');
  }
}
```

### Automated Cleanup

```javascript
// Schedule regular cleanup
async function scheduleCleanup() {
  console.log('Starting automated cleanup...');

  // Expired items cleanup
  const expiredCleanup = await call_tool('system_status', {
    operation: 'run_cleanup',
    cleanup_config: {
      operations: ['expired'],
      dry_run: false, // Actually perform cleanup
      batch_size: 100,
      require_confirmation: false,
      enable_backup: true,
    },
  });

  console.log(`Cleaned ${expiredCleanup.data.cleaned_items} expired items`);

  // Orphaned items cleanup
  const orphanCleanup = await call_tool('system_status', {
    operation: 'run_cleanup',
    cleanup_config: {
      operations: ['orphaned'],
      dry_run: false,
      batch_size: 50,
    },
  });

  console.log(`Cleaned ${orphanCleanup.data.cleaned_items} orphaned items`);
}

// Memory usage monitoring
async function monitorMemoryUsage() {
  const stats = await call_tool('system_status', {
    operation: 'stats',
    include_detailed_metrics: true,
  });

  const storageUsage = stats.data.storage_usage_mb;
  console.log(`Current storage usage: ${storageUsage}MB`);

  // Alert if usage is high
  if (storageUsage > 1000) {
    // 1GB threshold
    console.warn('⚠️ High storage usage detected');

    // Suggest cleanup
    console.log('Consider running cleanup operation');
  }
}
```

---

## Common Pitfalls and Solutions

### 1. Incorrect Scope Configuration

**Problem**: Items not appearing in search results due to scope mismatch.

```javascript
// ❌ Wrong - scope inconsistency
await call_tool('memory_store', {
  items: [
    {
      kind: 'entity',
      data: { title: 'User Service' },
      scope: { project: 'user-service', branch: 'main' }, // Stored in main branch
    },
  ],
});

await call_tool('memory_find', {
  query: 'user service',
  scope: { project: 'user-service', branch: 'develop' }, // Searching in develop branch
});

// ✅ Correct - consistent scope
await call_tool('memory_find', {
  query: 'user service',
  scope: { project: 'user-service', branch: 'main' }, // Same scope as storage
});
```

**Solution**: Always use consistent scope for storage and retrieval operations.

### 2. Overlooking Deduplication

**Problem**: Items not being stored due to deduplication without understanding why.

```javascript
// Check deduplication results
const result = await call_tool('memory_store', {
  items: [item],
  deduplication: {
    enabled: true,
    enable_audit_logging: true, // Enable logging to see why
  },
});

if (result.errors.length > 0) {
  console.log('Storage errors:', result.errors);
}

if (result.duplicates_found > 0) {
  console.log('Duplicates detected:', result.duplicates_found);
  console.log('Reasoning:', result.autonomous_context.reasoning);
}
```

**Solution**: Enable audit logging to understand deduplication decisions.

### 3. Ignoring TTL Policies

**Problem**: Important data disappearing unexpectedly due to TTL expiration.

```javascript
// ❌ Wrong - no TTL configuration for important data
await call_tool('memory_store', {
  items: [
    {
      kind: 'decision',
      data: { title: 'Critical architecture decision' },
      // No TTL config - will use default policy (30 days)
    },
  ],
});

// ✅ Correct - explicit TTL for important data
await call_tool('memory_store', {
  items: [
    {
      kind: 'decision',
      data: { title: 'Critical architecture decision' },
      ttl_config: {
        policy: 'permanent', // Never expires
        auto_extend: false,
      },
    },
  ],
});
```

**Solution**: Configure appropriate TTL policies based on data importance.

### 4. Inefficient Search Queries

**Problem**: Slow searches due to overly broad queries or missing optimization.

```javascript
// ❌ Wrong - broad search without limits
await call_tool('memory_find', {
  query: 'system', // Too generic
  // No limit, no scope, no optimization
});

// ✅ Correct - specific, optimized search
await call_tool('memory_find', {
  query: 'database connection pool configuration',
  scope: { project: 'infrastructure' },
  search_strategy: 'auto',
  limit: 10,
  optimization: {
    enable_caching: true,
    timeout_ms: 5000,
  },
});
```

**Solution**: Use specific queries, appropriate limits, and enable optimization features.

### 5. Missing Error Handling

**Problem**: Application crashes when MCP operations fail.

```javascript
// ❌ Wrong - no error handling
const result = await call_tool('memory_store', {
  items: items,
});
// Assumes result is always valid

// ✅ Correct - comprehensive error handling
async function safeStoreItems(items) {
  try {
    const result = await call_tool('memory_store', {
      items,
      processing: { enable_validation: true },
    });

    if (result.errors.length > 0) {
      console.warn(`Stored ${result.stored.length} items, ${result.errors.length} failed`);
      // Handle partial failures
      return { success: false, result };
    }

    return { success: true, result };
  } catch (error) {
    console.error('Storage failed:', error);
    // Handle network errors, rate limits, etc.
    return { success: false, error };
  }
}
```

**Solution**: Implement comprehensive error handling and partial failure management.

---

## Best Practices Summary

### Do's ✅

1. **Use consistent scoping** - Keep project/branch scope consistent for related operations
2. **Configure TTL appropriately** - Use permanent for critical data, short for temporary
3. **Enable intelligent deduplication** - Prevent duplicate knowledge while maintaining quality
4. **Optimize search queries** - Use specific terms, limits, and appropriate strategies
5. **Implement error handling** - Handle rate limits, network issues, and partial failures
6. **Monitor system health** - Regular health checks and performance monitoring
7. **Use batch operations** - Store multiple items efficiently when possible
8. **Enable audit logging** - Track important operations for debugging and compliance

### Don'ts ❌

1. **Don't ignore scope isolation** - Mixed scopes lead to confusing search results
2. **Don't store sensitive data** - Be mindful of what gets stored in memory
3. **Don't use generic search terms** - Leads to slow, irrelevant results
4. **Don't skip validation** - Always validate data before storage
5. **Don't ignore rate limits** - Handle them gracefully with retry logic
6. **Don't forget TTL policies** - Important data might expire unexpectedly
7. **Don't store very large items** - Use chunking for large content
8. **Don't disable deduplication** - Unless you have specific requirements

---

## Performance Benchmarks

Based on production testing with Cortex Memory MCP Server v2.0:

### Storage Performance

- **Single item storage**: ~50ms average
- **Batch storage (10 items)**: ~200ms average
- **Batch storage (100 items)**: ~800ms average
- **Large content with chunking**: ~1-2s depending on size

### Search Performance

- **Fast search (10 results)**: ~100ms average
- **Auto search (10 results)**: ~200ms average
- **Deep search with graph expansion**: ~500ms average
- **Cached search results**: ~10ms average

### System Limits

- **Maximum batch size**: 100 items per request
- **Maximum content size**: 1MB per item (configurable)
- **Maximum search results**: 100 per request
- **Rate limits**: 100 requests per minute per actor

### Recommended Configurations

- **Production batch size**: 20-50 items
- **Search result limit**: 10-25 items
- **Cache TTL**: 5-30 minutes for frequent searches
- **TTL policies**: Permanent for decisions, Long for documentation, Default for most data

This guide provides comprehensive coverage of MCP Cortex usage patterns and best practices. For specific implementation details, refer to the [API Reference](docs/API-REFERENCE.md) and [Troubleshooting Guide](docs/MCP-TROUBLESHOOTING.md).
