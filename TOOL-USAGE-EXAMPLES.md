# Cortex MCP Server - Tool Usage Examples for AI Agents

## 🎯 Quick Reference for AI Agents

### 1. memory_store - Store Knowledge Items

**Purpose**: Store knowledge with automatic semantic deduplication (85% similarity threshold)

**Basic Usage:**
```json
{
  "name": "memory_store",
  "arguments": {
    "items": [
      {
        "kind": "entity",
        "content": "User prefers dark mode interface",
        "metadata": { "source": "user-preferences", "timestamp": "2025-11-03" }
      }
    ]
  }
}
```

**Batch Storage:**
```json
{
  "name": "memory_store",
  "arguments": {
    "items": [
      {
        "kind": "decision",
        "content": "Use React for frontend development",
        "metadata": { "project": "web-app", "priority": "high" },
        "scope": { "project": "myproject", "branch": "main" }
      },
      {
        "kind": "todo",
        "content": "Implement user authentication",
        "metadata": { "assignee": "dev-team", "due": "2025-11-10" }
      }
    ]
  }
}
```

### 2. memory_find - Search Knowledge

**Basic Search:**
```json
{
  "name": "memory_find",
  "arguments": {
    "query": "user interface preferences",
    "limit": 10
  }
}
```

**Advanced Search with Filters:**
```json
{
  "name": "memory_find",
  "arguments": {
    "query": "authentication decisions",
    "limit": 5,
    "types": ["decision", "issue"],
    "mode": "auto",
    "expand": "relations",
    "scope": { "project": "myproject" }
  }
}
```

**Performance Modes:**
- `"fast"`: Keyword search, ≤20 results, fastest
- `"auto"`: Hybrid semantic+keyword, ≤50 results, balanced
- `"deep"`: Full semantic + graph expansion, ≤100 results, most comprehensive

### 3. system_status - System Operations (11-in-1)

#### Health & Monitoring
```json
{
  "name": "system_status",
  "arguments": {
    "operation": "health"
  }
}
```

```json
{
  "name": "system_status",
  "arguments": {
    "operation": "metrics",
    "summary": true
  }
}
```

#### Document Operations
```json
{
  "name": "system_status",
  "arguments": {
    "operation": "get_document",
    "parent_id": "doc-123",
    "include_metadata": true
  }
}
```

```json
{
  "name": "system_status",
  "arguments": {
    "operation": "reassemble_document",
    "parent_id": "doc-123",
    "min_completeness": 0.8
  }
}
```

#### Advanced Storage with Merge
```json
{
  "name": "system_status",
  "arguments": {
    "operation": "upsert_merge",
    "items": [
      {
        "kind": "entity",
        "content": "Updated user profile preferences",
        "metadata": { "version": "2.0" }
      }
    ],
    "similarity_threshold": 0.85,
    "merge_strategy": "intelligent"
  }
}
```

#### Maintenance Operations
```json
{
  "name": "system_status",
  "arguments": {
    "operation": "run_purge",
    "options": {
      "dry_run": true,
      "batch_size": 50
    }
  }
}
```

## 📚 Knowledge Types Explained

| Type | Use Case | Example |
|------|----------|---------|
| `entity` | Core concepts/objects | "User", "Database", "API" |
| `relation` | Relationships | "User HAS Profile", "API USES Database" |
| `observation` | Fine-grained data | "Response time: 200ms" |
| `section` | Document sections | "Chapter 1: Introduction" |
| `runbook` | Procedures | "Database backup steps" |
| `change` | Code changes | "Fixed login bug in auth service" |
| `issue` | Problems/tracking | "Login fails on Safari" |
| `decision` | Architecture decisions | "Use OAuth 2.0 for authentication" |
| `todo` | Tasks/actions | "Implement password reset" |
| `release_note` | Release info | "Version 2.1.0 released" |
| `ddl` | Schema changes | "CREATE TABLE users..." |
| `pr_context` | Pull request data | "PR #123: Add user registration" |
| `incident` | Incidents | "Database outage 2025-11-03" |
| `release` | Deployments | "Production deploy v2.1.0" |
| `risk` | Risk assessments | "Password complexity insufficient" |
| `assumption` | Assumptions | "Users have modern browsers" |

## 🎯 AI Agent Usage Patterns

### Pattern 1: Learn User Preferences
```javascript
// Store what you learn
await memory_store({
  items: [{
    kind: 'entity',
    content: 'User prefers concise responses',
    metadata: { category: 'communication-style' }
  }]
});

// Later, retrieve preferences
await memory_find({
  query: 'user communication preferences',
  types: ['entity', 'observation']
});
```

### Pattern 2: Track Project Decisions
```javascript
// Store decision
await memory_store({
  items: [{
    kind: 'decision',
    content: 'Use PostgreSQL for user data storage',
    metadata: { rationale: 'ACID compliance needed', alternatives: 'MongoDB, MySQL' },
    scope: { project: 'user-service', branch: 'main' }
  }]
});

// Find all decisions for project
await memory_find({
  query: 'database architecture decisions',
  types: ['decision'],
  scope: { project: 'user-service' }
});
```

### Pattern 3: Monitor System Health
```javascript
// Check system status
const health = await system_status({
  operation: 'health'
});

// Get performance metrics
const metrics = await system_status({
  operation: 'metrics',
  summary: true
});

// Take action based on results
if (health.status !== 'healthy') {
  await memory_store({
    items: [{
      kind: 'incident',
      content: `System health issue detected: ${health.status}`,
      metadata: { severity: 'high', timestamp: new Date().toISOString() }
    }]
  });
}
```

## 💡 Tips for AI Agents

1. **Always include metadata** - Adds context for future searches
2. **Use appropriate knowledge types** - Improves organization and retrieval
3. **Leverage scope** - Organize knowledge by project/branch/org
4. **Use semantic queries** - Natural language works better than keywords
5. **Check system health** - Monitor before complex operations
6. **Batch operations** - More efficient than individual calls
7. **Use upsert_merge** - Prevents duplicate knowledge entries

## 🔧 Error Handling

Always check response format:
```json
{
  "success": true/false,
  "stored": 1,
  "errors": [],
  "summary": { "total": 1, "stored": 1, "skipped_dedupe": 0 }
}
```

For search results:
```json
{
  "items": [...],
  "total": 5,
  "confidence": 0.85,
  "strategy": "auto"
}
```

---

**This guide provides comprehensive usage patterns for AI agents to maximize the value of Cortex Memory MCP Server's 3-tool interface while maintaining access to all 14 original capabilities.**