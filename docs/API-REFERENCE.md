# Cortex Memory MCP API Documentation

## Overview

The Cortex Memory MCP Server provides a basic API for knowledge storage, retrieval, and management through the Model Context Protocol (MCP). This document covers currently implemented API endpoints, their parameters, responses, and usage examples.

## Base Architecture

The system uses a Qdrant-only database layer:
- **Qdrant**: Vector similarity search, semantic understanding, and all data storage

⚠️ **Important**: This system uses Qdrant exclusively. PostgreSQL is not used or configured.

## Core API Methods

### 1. memory_store

Store knowledge items in the database with automatic deduplication and validation.

**Endpoint**: `memory_store`

**Parameters**:
```typescript
interface MemoryStoreRequest {
  items: KnowledgeItem[];
}

interface KnowledgeItem {
  kind: "entity" | "relation" | "observation" | "section" | "runbook" |
        "change" | "issue" | "decision" | "todo" | "release_note" |
        "ddl" | "pr_context" | "incident" | "release" | "risk" | "assumption";
  data: Record<string, any>;
  scope?: {
    project?: string;
    branch?: string;
    org?: string;
  };
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

*Store a single entity:*
```javascript
const result = await client.callTool("memory_store", {
  items: [{
    kind: "entity",
    data: {
      title: "User Authentication System",
      description: "OAuth 2.0 implementation with JWT tokens",
      status: "production"
    },
    scope: {
      project: "my-app",
      branch: "main",
      org: "my-company"
    }
  }]
});
```

*Store multiple related items:*
```javascript
const result = await client.callTool("memory_store", {
  items: [
    {
      kind: "decision",
      data: {
        title: "Use OAuth 2.0 for Authentication",
        rationale: "Industry standard with robust security features",
        alternatives: ["Basic Auth", "JWT-only", "Session-based"],
        impact: "High"
      }
    },
    {
      kind: "entity",
      data: {
        title: "OAuth Service Configuration",
        provider: "Auth0",
        scopes: ["openid", "profile", "email"]
      }
    },
    {
      kind: "todo",
      data: {
        title: "Implement token refresh mechanism",
        priority: "High",
        assignee: "backend-team"
      }
    }
  ]
});
```

**Error Handling**:
```javascript
const result = await client.callTool("memory_store", {
  items: invalidItems
});

if (result.errors.length > 0) {
  console.error('Storage errors:', result.errors);
  console.log('Successfully stored:', result.stored.length);
  console.log('Duplicates found:', result.autonomous_context.duplicates_found);
}
```

### 2. memory_find

Find knowledge items using basic semantic vector search.

**Endpoint**: `memory_find`

**Parameters**:
```typescript
interface MemoryFindRequest {
  query: string;
  scope?: {
    project?: string;
    branch?: string;
    org?: string;
  };
  types?: string[];
  mode?: "auto"; // Only "auto" mode is currently implemented
  limit?: number;
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
  match_type: "semantic"; // Only semantic matching implemented
}
```

**Current Limitations:**
- Only "auto" search mode available (fast/deep not implemented)
- No `confidence_average` calculation - basic similarity only
- No `user_message_suggestion` field - not implemented
- Only semantic matching (no exact, keyword, or fuzzy matching)
- No multi-strategy search capabilities

**Usage Examples**:

*Basic semantic search:*
```javascript
const result = await client.callTool("memory_find", {
  query: "How should I implement user authentication?",
  limit: 10
});
```

*Scoped search with type filtering:*
```javascript
const result = await client.callTool("memory_find", {
  query: "authentication security decisions",
  scope: {
    project: "my-app",
    branch: "main"
  },
  types: ["decision", "entity", "runbook"],
  mode: "auto",
  limit: 20
});
```

*Deep search with comprehensive analysis:*
```javascript
const result = await client.callTool("memory_find", {
  query: "database migration strategy for PostgreSQL",
  mode: "deep",
  types: ["ddl", "decision", "runbook", "incident"],
  limit: 50
});
```

**Search Modes**:

- **auto** (default): Basic semantic search using Qdrant vectors
- ~~fast~~: **Not implemented** - keyword-based search not available
- ~~deep~~: **Not implemented** - comprehensive analysis not available

**Result Processing**:
```javascript
const result = await client.callTool("memory_find", {
  query: "API rate limiting implementation"
});

// Process results by basic similarity score
const highScore = result.results.filter(r => r.confidence_score > 0.8);
const mediumScore = result.results.filter(r => r.confidence_score > 0.5 && r.confidence_score <= 0.8);

// Group by type
const byType = result.results.reduce((acc, item) => {
  acc[item.kind] = (acc[item.kind] || []).push(item);
  return acc;
}, {});

console.log(`Found ${result.total_count} results using ${result.autonomous_context.search_mode_used} mode`);
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

## Currently Implemented Features

### Basic Context Generation

Both `memory_store` and `memory_find` provide basic context:

```javascript
// Storage context
const storageResult = await client.callTool("memory_store", { items });
console.log(`Action: ${storageResult.autonomous_context.action_performed}`);
console.log(`Duplicates found: ${storageResult.autonomous_context.duplicates_found}`);
console.log(`Reasoning: ${storageResult.autonomous_context.reasoning}`);

// Search context
const searchResult = await client.callTool("memory_find", { query: "..." });
console.log(`Search mode: ${searchResult.autonomous_context.search_mode_used}`);
console.log(`Results found: ${searchResult.autonomous_context.results_found}`);
// Note: No confidence average or recommendations available
```

### Basic Duplicate Detection

The system detects basic duplicates using content similarity:

```javascript
const result = await client.callTool("memory_store", {
  items: [{
    kind: "entity",
    data: { title: "User Authentication System" }
  }]
});

if (result.autonomous_context.duplicates_found > 0) {
  console.log("Duplicate detected - existing similar item found");
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
await client.callTool("memory_store", {
  items: [item],
  scope: {
    project: "my-project",
    branch: "feature/new-auth",
    org: "my-company"
  }
});

// Search within scope
await client.callTool("memory_find", {
  query: "authentication",
  scope: {
    project: "my-project",
    branch: "main"  // Only search in main branch
  }
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
  const result = await client.callTool("memory_store", { items });
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
const items = Array.from({length: 100}, (_, i) => ({
  kind: "entity",
  data: { title: `Item ${i}` }
}));
await client.callTool("memory_store", { items });

// Avoid: Multiple individual requests
// for (const item of items) {
//   await client.callTool("memory_store", { items: [item] });
// }
```

### Search Optimization

Use appropriate search modes and limits:

```javascript
// Fast search for recent items
await client.callTool("memory_find", {
  query: "recent changes",
  mode: "fast",
  limit: 10
});

// Comprehensive search when needed
await client.callTool("memory_find", {
  query: "complex architectural decision",
  mode: "deep",
  limit: 50
});
```

### Scope Filtering

Use scope to reduce search space and improve performance:

```javascript
// Efficient scoped search
await client.callTool("memory_find", {
  query: "authentication",
  scope: { project: "my-app" },  // Limits search scope
  limit: 20
});
```

## Integration Examples

### Claude Code Integration

```javascript
// Store conversation context
await client.callTool("memory_store", {
  items: [{
    kind: "entity",
    data: {
      title: "Claude Code Session",
      conversation_id: session.id,
      context: "Discussed authentication implementation",
      date: new Date().toISOString()
    },
    scope: {
      project: "current-project"
    }
  }]
});

// Find relevant context
const context = await client.callTool("memory_find", {
  query: "authentication implementation decisions",
  types: ["decision", "entity"],
  limit: 5
});
```

### Development Workflow Integration

```javascript
// Store development decisions
await client.callTool("memory_store", {
  items: [{
    kind: "decision",
    data: {
      title: "Adopt TypeScript strict mode",
      rationale: "Improved type safety and developer experience",
      alternatives: ["JavaScript", "TypeScript loose mode"],
      impact: "Medium - requires type annotations"
    },
    scope: {
      project: "my-project",
      branch: "main"
    }
  }]
});

// Find relevant development context
const devContext = await client.callTool("memory_find", {
  query: "TypeScript configuration decisions",
  types: ["decision", "runbook"],
  scope: { project: "my-project" }
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
process.env.DEBUG = "cortex:*";

// Or use debug mode in search
await client.callTool("memory_find", {
  query: "debug test",
  mode: "deep"  // Provides more detailed analysis
});
```

## SDK and Tool Integration

This API is designed to work with MCP-compatible tools and SDKs. The primary interfaces are:

- **MCP Protocol**: Direct integration with Claude Code and other MCP clients
- **HTTP API**: RESTful endpoints for web applications
- **TypeScript SDK**: Type-safe client library for Node.js applications

For more integration examples and SDK documentation, see the Developer Guide.