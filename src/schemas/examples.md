# Cortex Memory MCP - Enhanced Tool Examples

This file provides comprehensive examples demonstrating all enhanced schema features including deduplication, TTL policies, truncation, insights, graph expansion, search strategies, and cleanup operations.

## Table of Contents

1. [Enhanced memory_store Examples](#enhanced-memory_store-examples)
2. [Enhanced memory_find Examples](#enhanced-memory_find-examples)
3. [System Status & Cleanup Examples](#system-status--cleanup-examples)
4. [Performance Monitoring Examples](#performance-monitoring-examples)
5. [Advanced Configuration Examples](#advanced-configuration-examples)
6. [Error Handling Examples](#error-handling-examples)

---

## Enhanced memory_store Examples

### Basic Memory Store (Backward Compatible)

```json
{
  "items": [
    {
      "kind": "decision",
      "scope": {
        "project": "my-app",
        "branch": "main"
      },
      "data": {
        "component": "authentication",
        "status": "accepted",
        "title": "Use OAuth 2.0 for authentication",
        "rationale": "Industry standard with good security properties"
      }
    }
  ]
}
```

### Enhanced Memory Store with Deduplication

```json
{
  "items": [
    {
      "kind": "section",
      "scope": {
        "project": "documentation",
        "branch": "main"
      },
      "content": "API endpoint for user management with full CRUD operations",
      "ttl_config": {
        "policy": "long",
        "expires_at": "2025-12-31T23:59:59Z",
        "auto_extend": true,
        "extend_threshold_days": 7,
        "max_extensions": 3
      },
      "truncation_config": {
        "enabled": true,
        "max_chars": 8000,
        "mode": "intelligent",
        "preserve_structure": true,
        "add_indicators": true,
        "safety_margin": 0.1
      },
      "insights_config": {
        "enabled": false,
        "generate_insights": false,
        "insight_types": ["summary", "trends"],
        "confidence_threshold": 0.7,
        "max_insights": 5
      }
    }
  ],
  "deduplication": {
    "enabled": true,
    "merge_strategy": "intelligent",
    "similarity_threshold": 0.85,
    "check_within_scope_only": true,
    "max_history_hours": 168,
    "dedupe_window_days": 30,
    "allow_newer_versions": true,
    "enable_audit_logging": true,
    "enable_intelligent_merging": true,
    "preserve_merge_history": false,
    "cross_scope_deduplication": false,
    "prioritize_same_scope": true,
    "max_items_to_check": 100,
    "batch_size": 50
  },
  "global_ttl": {
    "policy": "default",
    "auto_extend": false
  },
  "global_truncation": {
    "enabled": true,
    "max_chars": 10000,
    "mode": "intelligent",
    "preserve_structure": true,
    "add_indicators": true
  },
  "processing": {
    "enable_validation": true,
    "enable_async_processing": false,
    "batch_processing": true,
    "return_summaries": true,
    "include_metrics": true
  }
}
```

### Entity with Relations

```json
{
  "items": [
    {
      "kind": "entity",
      "scope": {
        "project": "user-management",
        "branch": "feature/user-profiles"
      },
      "data": {
        "entity_type": "user",
        "name": "john_doe",
        "data": {
          "email": "john@example.com",
          "role": "developer",
          "department": "engineering",
          "join_date": "2023-01-15"
        }
      },
      "idempotency_key": "user-john_doe-2023-01-15",
      "tags": {
        "active": true,
        "verified": true
      }
    }
  ],
  "deduplication": {
    "enabled": true,
    "merge_strategy": "combine",
    "similarity_threshold": 0.9
  }
}
```

### Multiple Knowledge Types with Mixed Configurations

```json
{
  "items": [
    {
      "kind": "todo",
      "scope": {
        "project": "infrastructure",
        "branch": "main",
        "service": "kubernetes"
      },
      "data": {
        "title": "Upgrade ingress controller to latest version",
        "status": "pending",
        "priority": "high",
        "due_date": "2025-01-15T10:00:00Z",
        "dependencies": ["security-audit-complete"]
      },
      "ttl_config": {
        "policy": "short",
        "expires_at": "2025-02-01T23:59:59Z"
      }
    },
    {
      "kind": "incident",
      "scope": {
        "project": "production",
        "org": "company"
      },
      "data": {
        "title": "Database connection pool exhaustion",
        "severity": "critical",
        "impact": "API downtime for 15 minutes",
        "resolution_status": "resolved",
        "timeline": [
          {
            "timestamp": "2025-01-10T14:30:00Z",
            "event": "Alert triggered for high connection count",
            "actor": "monitoring-system"
          },
          {
            "timestamp": "2025-01-10T14:35:00Z",
            "event": "Database connections exceeded pool limit",
            "actor": "application"
          },
          {
            "timestamp": "2025-01-10T14:45:00Z",
            "event": "Pool size increased, connections restored",
            "actor": "ops-team"
          }
        ]
      },
      "ttl_config": {
        "policy": "permanent"
      }
    }
  ],
  "processing": {
    "enable_validation": true,
    "include_metrics": true
  }
}
```

---

## Enhanced memory_find Examples

### Basic Search (Backward Compatible)

```json
{
  "query": "authentication methods",
  "limit": 10,
  "types": ["decision", "section"],
  "mode": "auto"
}
```

### Advanced Search with Graph Expansion

```json
{
  "query": "database migration strategies",
  "search_strategy": "deep",
  "scope": {
    "project": "backend-services",
    "branch": "main"
  },
  "types": ["decision", "ddl", "incident", "risk"],
  "limit": 20,
  "offset": 0,
  "graph_expansion": {
    "enabled": true,
    "expansion_type": "relations",
    "max_depth": 3,
    "max_nodes": 200,
    "include_metadata": true,
    "relation_types": ["implements", "resolves", "documents"],
    "direction": "both"
  },
  "ttl_filters": {
    "include_expired": false,
    "expires_after": "2025-01-01T00:00:00Z",
    "ttl_policies": ["long", "permanent"]
  },
  "filters": {
    "created_after": "2024-01-01T00:00:00Z",
    "tags": ["database", "migration"],
    "confidence_min": 0.7
  },
  "formatting": {
    "include_content": true,
    "include_metadata": true,
    "include_relations": true,
    "include_confidence_scores": true,
    "include_similarity_explanation": true,
    "highlight_matches": true,
    "max_content_length": 1500
  },
  "optimization": {
    "enable_caching": true,
    "cache_ttl_seconds": 600,
    "parallel_search": true,
    "timeout_ms": 15000
  },
  "analytics": {
    "track_search_metrics": true,
    "log_search_query": false,
    "include_performance_metrics": true,
    "record_user_feedback": true
  }
}
```

### Time-Restricted Search

```json
{
  "query": "performance optimization",
  "search_strategy": "auto",
  "filters": {
    "created_after": "2024-06-01T00:00:00Z",
    "created_before": "2024-12-31T23:59:59Z",
    "updated_after": "2024-11-01T00:00:00Z"
  },
  "ttl_filters": {
    "include_expired": true,
    "expires_before": "2025-06-01T00:00:00Z"
  }
}
```

### Entity-Centric Search with Relations

```json
{
  "query": "user authentication flows",
  "types": ["entity", "relation", "observation"],
  "graph_expansion": {
    "enabled": true,
    "expansion_type": "all",
    "max_depth": 2,
    "max_nodes": 50,
    "direction": "outgoing"
  },
  "formatting": {
    "include_content": true,
    "include_relations": true,
    "include_metadata": true,
    "highlight_matches": true
  }
}
```

### Search with Metadata Filtering

```json
{
  "query": "security vulnerabilities",
  "filters": {
    "tags": ["security", "vulnerability", "cve"],
    "metadata": {
      "severity": ["critical", "high"],
      "component": "authentication"
    },
    "confidence_min": 0.8
  },
  "ttl_filters": {
    "ttl_policies": ["long", "permanent"]
  }
}
```

---

## System Status & Cleanup Examples

### Basic Health Check

```json
{
  "operation": "health",
  "response_formatting": {
    "summary": true,
    "include_timestamps": true
  }
}
```

### Comprehensive System Statistics

```json
{
  "operation": "stats",
  "scope": {
    "project": "production",
    "org": "company"
  },
  "stats_period_days": 7,
  "include_detailed_metrics": true,
  "response_formatting": {
    "summary": false,
    "verbose": true,
    "include_raw_data": true,
    "include_timestamps": true
  }
}
```

### Safe Cleanup Operation (Dry Run)

```json
{
  "operation": "run_cleanup",
  "cleanup_config": {
    "operations": ["expired", "orphaned", "duplicate"],
    "scope_filters": {
      "project": "test-project",
      "branch": "feature/obsolete"
    },
    "require_confirmation": true,
    "enable_backup": true,
    "batch_size": 50,
    "max_batches": 10,
    "dry_run": true
  },
  "response_formatting": {
    "summary": true,
    "verbose": true
  }
}
```

### Confirm Cleanup Operation

```json
{
  "operation": "confirm_cleanup",
  "cleanup_token": "cleanup-token-abc123-2025-01-10",
  "response_formatting": {
    "verbose": true
  }
}
```

### Cleanup Statistics

```json
{
  "operation": "get_cleanup_statistics",
  "stats_period_days": 30,
  "report_limit": 20,
  "scope": {
    "project": "all"
  }
}
```

### Performance Monitoring

```json
{
  "operation": "get_performance_trends",
  "performance_window_hours": 24,
  "include_detailed_metrics": true,
  "response_formatting": {
    "summary": false,
    "include_raw_data": false
  }
}
```

### Document Management

```json
{
  "operation": "reassemble_document",
  "document_id": "550e8400-e29b-41d4-a716-446655440000",
  "response_formatting": {
    "verbose": true,
    "include_timestamps": true
  }
}
```

### Rate Limiting Status

```json
{
  "operation": "get_rate_limit_status",
  "response_formatting": {
    "summary": false,
    "verbose": true
  }
}
```

---

## Performance Monitoring Examples

### Basic Metrics Query

```json
{
  "operation": "get_metrics",
  "time_window": {
    "last_hours": 24
  },
  "categories": ["performance", "memory", "errors"],
  "output": {
    "format": "json",
    "limit": 1000
  }
}
```

### Advanced Trend Analysis

```json
{
  "operation": "get_trends",
  "time_window": {
    "last_days": 7
  },
  "categories": ["performance", "rate_limiting"],
  "aggregation": {
    "interval": "hour",
    "functions": ["avg", "min", "max"],
    "group_by": ["tool_name", "operation_type"]
  },
  "filters": {
    "tool_name": "memory_find",
    "min_value": 100
  },
  "output": {
    "format": "json",
    "include_charts": true,
    "limit": 500
  }
}
```

### Alert Configuration

```json
{
  "operation": "get_alerts",
  "alert_thresholds": {
    "response_time_ms": 5000,
    "error_rate_percent": 5.0,
    "memory_usage_mb": 1024,
    "cpu_usage_percent": 80
  },
  "time_window": {
    "last_hours": 1
  },
  "output": {
    "format": "json",
    "include_raw_data": true
  }
}
```

### System Health Check

```json
{
  "operation": "system_health",
  "time_window": {
    "last_hours": 1
  },
  "categories": ["performance", "memory", "storage", "network"],
  "output": {
    "format": "json",
    "verbose": true
  }
}
```

---

## Advanced Configuration Examples

### Complex Deduplication Strategy

```json
{
  "items": [
    {
      "kind": "section",
      "content": "API documentation for user endpoints",
      "scope": { "project": "api-docs" }
    }
  ],
  "deduplication": {
    "enabled": true,
    "merge_strategy": "intelligent",
    "similarity_threshold": 0.8,
    "check_within_scope_only": false,
    "max_history_hours": 720,
    "dedupe_window_days": 90,
    "allow_newer_versions": true,
    "enable_audit_logging": true,
    "enable_intelligent_merging": true,
    "preserve_merge_history": true,
    "max_merge_history_entries": 20,
    "cross_scope_deduplication": true,
    "prioritize_same_scope": true,
    "time_based_deduplication": true,
    "max_age_for_dedupe_days": 180,
    "respect_update_timestamps": true,
    "max_items_to_check": 500,
    "batch_size": 100,
    "enable_parallel_processing": true
  }
}
```

### Advanced TTL Configuration

```json
{
  "items": [
    {
      "kind": "observation",
      "data": {
        "entity_type": "decision",
        "entity_id": "123e4567-e89b-12d3-a456-426614174000",
        "observation": "Implementation completed successfully",
        "observation_type": "status"
      },
      "ttl_config": {
        "policy": "long",
        "expires_at": "2026-12-31T23:59:59Z",
        "auto_extend": true,
        "extend_threshold_days": 30,
        "max_extensions": 5
      }
    }
  ],
  "global_ttl": {
    "policy": "default",
    "auto_extend": true,
    "extend_threshold_days": 7,
    "max_extensions": 3
  }
}
```

### Intelligent Truncation

```json
{
  "items": [
    {
      "kind": "section",
      "content": "Very long documentation content that exceeds normal limits...",
      "truncation_config": {
        "enabled": true,
        "max_chars": 5000,
        "max_tokens": 2000,
        "mode": "intelligent",
        "preserve_structure": true,
        "add_indicators": true,
        "indicator": "[Content truncated for brevity...]",
        "safety_margin": 0.15,
        "auto_detect_content_type": true,
        "enable_smart_truncation": true
      }
    }
  ]
}
```

---

## Error Handling Examples

### Validation Error Response

```json
{
  "error": {
    "type": "ValidationError",
    "message": "Memory store validation failed: items: At least one item is required",
    "field": "items",
    "code": "VALIDATION_ERROR"
  },
  "request_id": "req_123456789",
  "timestamp": "2025-01-10T15:30:00Z"
}
```

### Configuration Error Response

```json
{
  "error": {
    "type": "ValidationError",
    "message": "Invalid merge strategy. Must be one of: skip, prefer_existing, prefer_newer, combine, intelligent",
    "field": "deduplication.merge_strategy",
    "code": "VALIDATION_ERROR"
  },
  "request_id": "req_123456790",
  "timestamp": "2025-01-10T15:31:00Z"
}
```

### Operation-Specific Error Response

```json
{
  "error": {
    "type": "OperationError",
    "message": "Missing required parameters for the specified operation",
    "operation": "get_document",
    "missing_field": "document_id",
    "code": "MISSING_REQUIRED_PARAMETER"
  },
  "request_id": "req_123456791",
  "timestamp": "2025-01-10T15:32:00Z"
}
```

---

## Response Format Examples

### Enhanced Memory Store Response

```json
{
  "success": true,
  "items_stored": 3,
  "items_merged": 1,
  "items_duplicated": 0,
  "operation_id": "store_op_123456789",
  "metrics": {
    "processing_time_ms": 1250,
    "deduplication_checks": 50,
    "similarity_scores": [0.92, 0.78, 0.65],
    "merge_operations": 1,
    "truncation_applied": 0
  },
  "results": [
    {
      "item_id": "item_550e8400-e29b-41d4-a716-446655440000",
      "status": "stored",
      "kind": "decision",
      "confidence": 0.95,
      "ttl_expires_at": "2025-07-10T15:30:00Z",
      "applied_truncation": false,
      "applied_deduplication": false
    },
    {
      "item_id": "item_550e8400-e29b-41d4-a716-446655440001",
      "status": "merged",
      "kind": "section",
      "merged_with": "item_550e8400-e29b-41d4-a716-446655440002",
      "similarity_score": 0.89,
      "applied_truncation": false,
      "applied_deduplication": true
    }
  ],
  "warnings": [
    {
      "type": "content_truncation",
      "message": "Item content was truncated to fit within limits",
      "item_id": "item_550e8400-e29b-41d4-a716-446655440003",
      "original_length": 15000,
      "truncated_length": 10000
    }
  ],
  "timestamp": "2025-01-10T15:30:00Z"
}
```

### Enhanced Memory Find Response

```json
{
  "success": true,
  "query": "authentication methods",
  "search_strategy": "deep",
  "results_count": 15,
  "total_available": 47,
  "operation_id": "find_op_123456789",
  "metrics": {
    "search_time_ms": 890,
    "vectors_searched": 1500,
    "graph_nodes_explored": 85,
    "relations_found": 23,
    "cache_hit": false,
    "confidence_scores": [0.94, 0.91, 0.88, 0.85]
  },
  "results": [
    {
      "item_id": "item_550e8400-e29b-41d4-a716-446655440000",
      "kind": "decision",
      "score": 0.94,
      "content": "Use OAuth 2.0 with JWT tokens for authentication...",
      "metadata": {
        "created_at": "2024-11-15T10:00:00Z",
        "updated_at": "2024-12-01T14:30:00Z",
        "scope": { "project": "auth-service" },
        "tags": ["authentication", "oauth", "jwt"]
      },
      "relations": [
        {
          "relation_id": "rel_123",
          "type": "implements",
          "target_item_id": "item_550e8400-e29b-41d4-a716-446655440001",
          "confidence": 0.92
        }
      ],
      "similarity_explanation": "High semantic similarity in authentication context",
      "highlighted_content": "Use <mark>OAuth 2.0</mark> with <mark>JWT</mark> tokens for authentication...",
      "ttl_info": {
        "policy": "long",
        "expires_at": "2025-12-31T23:59:59Z"
      }
    }
  ],
  "graph_expansion_summary": {
    "nodes_explored": 85,
    "relations_found": 23,
    "max_depth_reached": 3,
    "expansion_time_ms": 450
  },
  "pagination": {
    "limit": 20,
    "offset": 0,
    "has_more": true,
    "next_offset": 20
  },
  "timestamp": "2025-01-10T15:35:00Z"
}
```

### System Status Response

```json
{
  "success": true,
  "operation": "health",
  "timestamp": "2025-01-10T15:40:00Z",
  "status": {
    "overall": "healthy",
    "database": "connected",
    "vector_store": "operational",
    "cache": "active",
    "rate_limiter": "functional"
  },
  "capabilities": {
    "vector_operations": true,
    "deduplication": true,
    "ttl_management": true,
    "truncation": true,
    "graph_expansion": true,
    "performance_monitoring": true,
    "cleanup_operations": true
  },
  "metrics": {
    "uptime_ms": 2592000000,
    "total_items": 15234,
    "active_connections": 8,
    "memory_usage_mb": 512,
    "cache_hit_rate": 0.73,
    "average_response_time_ms": 245,
    "error_rate_percent": 0.2
  },
  "resource_utilization": {
    "cpu_usage_percent": 35,
    "memory_usage_percent": 42,
    "disk_usage_percent": 28,
    "network_io_mbps": 12
  }
}
```

These examples demonstrate the full capabilities of the enhanced Cortex Memory MCP schemas, including advanced deduplication strategies, comprehensive TTL management, intelligent truncation, graph expansion, sophisticated search capabilities, and comprehensive system monitoring.
