# Cortex MCP API - Short Reference

## Overview
Cortex Memory MCP provides persistent knowledge management with 16 supported types, semantic deduplication, and intelligent search capabilities.

## Quick Start

### Store Knowledge Items
```typescript
// Store items with automatic deduplication and expiry calculation
await memory_store({
  items: [{
    kind: "entity",
    content: "User authentication service",
    scope: { project: "my-app", org: "default" },
    data: { type: "service", status: "active" }
  }]
})
```

### Search Knowledge Items
```typescript
// Search with semantic matching and graph expansion
await memory_find({
  query: "authentication decisions",
  scope: { project: "my-app" },
  types: ["decision"],
  mode: "auto",
  limit: 10,
  expand: "relations"
})
```

## Response Shapes

### Store Response
```typescript
{
  results: [{
    id: "uuid-string",
    status: "inserted" | "updated" | "skipped_dedupe" | "deleted",
    kind: "entity" | "decision" | "issue" | // ...16 types
    created_at: "2025-01-01T00:00:00.000Z"
  }],
  errors: [{
    index: 0,
    error_code: "validation_error" | "business_rule_blocked",
    message: "Description",
    field?: "kind"
  }],
  summary: {
    total_processed: 5,
    successful: 4,
    failed: 1,
    skipped_dedupe: 0
  },
  batch_id: "uuid-string"
}
```

### Find Response
```typescript
{
  results: [{
    id: "uuid-string",
    kind: "entity",
    scope: { project: "my-app", org: "default" },
    content: "Item content",
    data: { /* structured data */ },
    created_at: "2025-01-01T00:00:00.000Z",
    similarity_score: 0.95
  }],
  total_count: 42,
  autonomous_context: {
    search_mode_used: "auto" | "deep" | "fast",
    results_found: 10,
    confidence_average: 0.87,
    user_message_suggestion: "✅ Found relevant items"
  }
}
```

## Supported Knowledge Types (16)

**Core Types:** `entity`, `relation`, `observation`
**Project Management:** `todo`, `issue`, `decision`, `change`, `release`
**Technical:** `ddl`, `runbook`, `pr_context`, `incident`
**Organizational:** `section`, `release_note`, `risk`, `assumption`

## Current Limits

**Operations:**
- Store: 100 items per batch, 10MB content per item
- Search: 10,000 results max, semantic matching enabled
- Batches: 100 items/batch for processing operations

**Features:**
- Scope isolation: project, branch, org levels
- Expiry: Automatic TTL calculation (default=30d, short=24h, long=90d, permanent=∞)
- Deduplication: Content hashing with similarity scoring
- Graph expansion: Relations, parents, children traversal
- Validation: Business rules and schema validation per type

## Error Handling
- Business rule violations return `business_rule_blocked` status
- Validation errors return `validation_error` with field details
- Batch processing continues on individual item failures
- Comprehensive logging with structured error context

## Search Modes
- `fast`: Exact keyword matching (≤20 results)
- `auto`: Smart hybrid approach (≤50 results)
- `deep`: Semantic + graph expansion (≤100 results)

## Scope Management
Default org scope `{org: 'default'}` applied automatically when no scope provided.
Use project/branch/org combinations for proper isolation and cross-project querying.