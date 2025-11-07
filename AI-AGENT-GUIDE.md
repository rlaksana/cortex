# Cortex Memory MCP Server - AI Agent Guide

## 🎯 Overview

Cortex Memory MCP Server provides **exactly 3 tools** for AI agents to perform advanced knowledge management operations with semantic search and vector database capabilities.

## 📋 Tool Interface (3 Tools Total)

### 1. `memory_store`

**Purpose**: Store knowledge items with semantic deduplication

```json
{
  "name": "memory_store",
  "arguments": {
    "items": [
      {
        "kind": "entity|relation|observation|section|runbook|change|issue|decision|todo|release_note|ddl|pr_context|incident|release|risk|assumption",
        "content": "Knowledge content",
        "metadata": { "additional": "data" },
        "scope": {
          "project": "project-name",
          "branch": "branch-name",
          "org": "organization-name"
        }
      }
    ]
  }
}
```

### 2. `memory_find`

**Purpose**: Search knowledge items with intelligent semantic strategies

```json
{
  "name": "memory_find",
  "arguments": {
    "query": "search query",
    "limit": 10,
    "types": ["entity", "decision"],
    "scope": { "project": "project-name" },
    "mode": "fast|auto|deep",
    "expand": "relations|parents|children|none"
  }
}
```

### 3. `system_status`

**Purpose**: Comprehensive system operations (11 operations in 1 tool)

```json
{
  "name": "system_status",
  "arguments": {
    "operation": "health|stats|telemetry|metrics|get_document|reassemble_document|get_document_with_chunks|run_purge|get_purge_reports|get_purge_statistics|upsert_merge"
    // Additional parameters depend on operation
  }
}
```

## 📊 `system_status` Operations (11 in 1)

| Operation                  | Description                   | Key Parameters                                    |
| -------------------------- | ----------------------------- | ------------------------------------------------- |
| `health`                   | Database connection health    | None                                              |
| `stats`                    | Database statistics           | `scope`                                           |
| `telemetry`                | Performance telemetry         | None                                              |
| `metrics`                  | System metrics                | `summary` (boolean)                               |
| `get_document`             | Retrieve document with chunks | `parent_id`, `include_metadata`                   |
| `reassemble_document`      | Reassemble from chunks        | `parent_id`, `min_completeness`                   |
| `get_document_with_chunks` | Get document + chunks         | `doc_id`, `options`                               |
| `run_purge`                | Run TTL cleanup               | `options` (dry_run, batch_size)                   |
| `get_purge_reports`        | Recent purge reports          | `limit`                                           |
| `get_purge_statistics`     | Purge statistics              | `days`                                            |
| `upsert_merge`             | Store with intelligent merge  | `items`, `similarity_threshold`, `merge_strategy` |

## 🎯 Benefits for AI Agents

✅ **Simplified Interface**: Only 3 tool names to remember instead of 14
✅ **Zero Functionality Loss**: All original features preserved
✅ **Consistent Parameters**: Same parameters as original tools
✅ **AI-Optimized Responses**: Boolean success + essential data
✅ **Single Dispatcher**: Efficient routing through `system_status.operation`

## 📚 Migration from Original 14 Tools

| Original Tool                | New Usage                                                     |
| ---------------------------- | ------------------------------------------------------------- |
| `database_health`            | `system_status` + `{"operation": "health"}`                   |
| `database_stats`             | `system_status` + `{"operation": "stats"}`                    |
| `telemetry_report`           | `system_status` + `{"operation": "telemetry"}`                |
| `system_metrics`             | `system_status` + `{"operation": "metrics"}`                  |
| `memory_get_document`        | `system_status` + `{"operation": "get_document"}`             |
| `reassemble_document`        | `system_status` + `{"operation": "reassemble_document"}`      |
| `get_document_with_chunks`   | `system_status` + `{"operation": "get_document_with_chunks"}` |
| `ttl_worker_run_with_report` | `system_status` + `{"operation": "run_purge"}`                |
| `get_purge_reports`          | `system_status` + `{"operation": "get_purge_reports"}`        |
| `get_purge_statistics`       | `system_status` + `{"operation": "get_purge_statistics"}`     |
| `memory_upsert_with_merge`   | `system_status` + `{"operation": "upsert_merge"}`             |

## 🔧 Usage Examples

### Basic Memory Operations

```javascript
// Store knowledge
await callTool('memory_store', {
  items: [
    {
      kind: 'entity',
      content: 'User prefers dark mode',
      metadata: { source: 'user-settings' },
    },
  ],
});

// Search knowledge
await callTool('memory_find', {
  query: 'user preferences',
  limit: 5,
});
```

### System Operations

```javascript
// Check database health
await callTool('system_status', {
  operation: 'health',
});

// Get system metrics summary
await callTool('system_status', {
  operation: 'metrics',
  summary: true,
});

// Retrieve document
await callTool('system_status', {
  operation: 'get_document',
  parent_id: 'doc-123',
  include_metadata: true,
});
```

## 🎉 Ready for AI Agent Usage

The Cortex Memory MCP Server is now optimized for AI agents with:

- **3 simple tools** instead of 14 complex ones
- **100% functionality preserved** through intelligent consolidation
- **Consistent interface** across all operations
- **Production-ready** with full error handling and monitoring

**Server Configuration**:

```toml
[mcp_servers.cortex]
type = 'stdio'
command = "node"
args = ["D:\\WORKSPACE\\tools-node\\mcp-cortex\\dist\\index.js"]
```

---

**Version**: 2.0.0
**Last Updated**: 2025-11-03
**For**: AI Agents exclusively
