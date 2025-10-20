# Cortex Memory MCP - Comprehensive API Documentation

## Overview

The Cortex Memory MCP (Model Context Protocol) server provides comprehensive knowledge management capabilities with 16 distinct knowledge types, advanced search functionality, deduplication, pagination, and observability features.

## Table of Contents

1. [Knowledge Types](#knowledge-types)
2. [Core Operations](#core-operations)
3. [Advanced Features](#advanced-features)
4. [Error Handling](#error-handling)
5. [Observability](#observability)
6. [Performance Considerations](#performance-considerations)
7. [Migration Guide](#migration-guide)
8. [Testing](#testing)

## Knowledge Types

The system supports 16 knowledge types, each with specific validation rules and immutability constraints:

### Core Documentation Types
- **section**: Documentation chunks with markdown/text body
- **runbook**: Operational procedures and playbooks
- **decision**: ADRs (Architecture Decision Records) with rationale

### Project Management Types
- **issue**: Issue tracking with root cause and resolution
- **todo**: Task tracking with status and priority
- **change**: Change log entries for tracking modifications
- **release**: Release management with scope and version
- **risk**: Risk identification with impact probability and mitigation
- **assumption**: Assumption tracking with validation status

### Development & Technical Types
- **pr_context**: Pull request metadata and context
- **ddl**: Database schema changes (DDL history)
- **incident**: Incident reports with impact, severity, timeline, and RCA

### Graph Extension Types
- **entity**: Flexible user-defined entities (graph extension)
- **relation**: Links between any knowledge items (graph extension)
- **observation**: Fine-grained facts attached to entities (graph extension)
- **release_note**: Release documentation and changelogs

## Core Operations

### Memory Store (`memory_store`)

Store new knowledge items or update existing ones with comprehensive validation and deduplication.

#### Request Format
```typescript
interface MemoryStoreRequest {
  items: EnhancedKnowledgeItem[];
  correlation?: CorrelationContext;
}

interface EnhancedKnowledgeItem {
  kind: KnowledgeType; // One of the 16 knowledge types
  scope: {
    project?: string;
    branch?: string;
    org?: string;
    [key: string]: unknown;
  };
  data: KnowledgeData; // Type-specific data structure
  tags?: Record<string, string>;
  idempotency_key?: string; // For deduplication
  source?: {
    actor?: string;
    timestamp?: string;
    [key: string]: unknown;
  };
}
```

#### Response Format
```typescript
interface MemoryStoreResponse {
  stored: StoreResult[];
  errors: StoreError[];
  autonomous_context: {
    action_performed: 'created' | 'updated' | 'skipped_dedupe' | 'failed';
    similar_items_checked: number;
    duplicates_found: number;
    contradictions_detected: boolean;
    recommendation: string;
    reasoning: string;
    user_message_suggestion: string;
  };
  correlation?: CorrelationContext;
}
```

#### Features
- **Auto-deduplication**: Uses content hashing to detect duplicates
- **Similarity detection**: Identifies similar items and suggests updates
- **Immutability protection**: Respects protected status of certain knowledge types
- **Branch isolation**: Enforces project/branch scoping
- **Performance monitoring**: Tracks operation duration and memory usage

#### Usage Examples

**Creating a Section**
```typescript
const response = await memory_store({
  items: [{
    kind: 'section',
    scope: { project: 'my-app', branch: 'main' },
    data: {
      title: 'API Authentication',
      heading: 'API Authentication',
      body_md: '# API Authentication\n\nUses OAuth 2.0 with JWT tokens...',
    },
  }],
});
```

**Creating a Decision**
```typescript
const response = await memory_store({
  items: [{
    kind: 'decision',
    scope: { project: 'my-app', branch: 'main' },
    data: {
      title: 'Use OAuth 2.0',
      component: 'auth',
      status: 'proposed',
      rationale: 'Industry standard, well-supported',
      alternatives_considered: ['Basic Auth', 'JWT only'],
      consequences: 'Requires additional infrastructure',
    },
  }],
});
```

### Memory Find (`memory_find`)

Search knowledge items with advanced query enhancement, pagination, and graph traversal.

#### Request Format
```typescript
interface MemoryFindRequest {
  query: string;
  scope?: Record<string, unknown>;
  types?: string[];
  top_k?: number;
  mode?: 'auto' | 'fast' | 'deep';
  traverse?: TraversalOptions;
  enableAutoFix?: boolean;
  enableSuggestions?: boolean;
  correlation?: CorrelationContext;
}

interface TraversalOptions {
  depth?: number;
  relation_types?: string[];
  direction?: 'incoming' | 'outgoing' | 'both';
  start_entity_type?: string;
  start_entity_id?: string;
}
```

#### Response Format
```typescript
interface MemoryFindResponse {
  hits: FindHit[];
  suggestions: string[];
  autonomous_metadata: {
    strategy_used: string;
    mode_requested: string;
    mode_executed: string;
    confidence: 'high' | 'medium' | 'low';
    total_results: number;
    avg_score: number;
    recommendation: string;
    user_message_suggestion: string;
  };
  query_enhancement?: EnhancedQuery;
  graph?: GraphResult;
  correlation?: CorrelationContext;
}

interface FindHit {
  kind: string;
  id: string;
  title: string;
  snippet: string;
  score: number;
  confidence: number;
  scope?: Record<string, unknown>;
  updated_at: string;
  route_used: string;
}
```

#### Features
- **Query enhancement**: Auto-correction of typos and query normalization
- **Multi-mode search**: Fast (basic), deep (comprehensive), auto (intelligent)
- **Scope filtering**: Project/branch/org level isolation
- **Graph traversal**: Navigate relationships between knowledge items
- **Ranking algorithm**: Relevance scoring with FTS, recency, and proximity factors

#### Usage Examples

**Basic Search**
```typescript
const response = await memory_find({
  query: 'authentication OAuth',
  types: ['section', 'decision'],
  top_k: 10,
  mode: 'auto',
});
```

**Search with Graph Traversal**
```typescript
const response = await memory_find({
  query: 'authentication',
  traverse: {
    depth: 2,
    relation_types: ['implements', 'depends_on'],
    direction: 'both',
  },
});
```

### Delete Operations (`soft_delete`)

Soft delete knowledge items with cascade support and immutability protection.

#### Request Format
```typescript
interface DeleteRequest {
  entity_type: KnowledgeType;
  entity_id: string;
  cascade_relations?: boolean;
  correlation?: CorrelationContext;
}
```

#### Response Format
```typescript
interface DeleteResult {
  id: string;
  entity_type: string;
  status: 'deleted' | 'not_found' | 'immutable' | 'error';
  message?: string;
  cascaded_relations?: number;
}
```

#### Features
- **Soft delete**: Preserves data with deleted_at timestamps
- **Cascade operations**: Optionally delete related items
- **Immutability protection**: Blocks deletion of protected items
- **Comprehensive logging**: Detailed audit trail

#### Usage Examples

**Simple Delete**
```typescript
const response = await soft_delete({
  entity_type: 'section',
  entity_id: 'section-uuid',
});
```

**Cascade Delete**
```typescript
const response = await soft_delete({
  entity_type: 'decision',
  entity_id: 'decision-uuid',
  cascade_relations: true,
});
```

## Advanced Features

### Pagination and Sorting

The system supports comprehensive pagination and sorting for all list operations.

#### Pagination Parameters
```typescript
interface PaginationParams {
  page?: number;        // Page number (default: 1)
  limit?: number;       // Items per page (default: 50, max: 1000)
  offset?: number;      // Manual offset (alternative to page)
}
```

#### Sorting Parameters
```typescript
interface SortParams {
  sort_by?: string;           // Field to sort by
  sort_order?: 'asc' | 'desc'; // Sort direction (default: 'desc')
}
```

#### Sort Options by Knowledge Type
- **section**: updated_at, created_at, heading, citation_count
- **decision**: updated_at, created_at, status, title, component
- **issue**: updated_at, created_at, status, severity, title
- **todo**: updated_at, created_at, status, priority, title
- **entity**: updated_at, created_at, entity_type, name
- **runbook**: updated_at, created_at, service
- **default**: updated_at, created_at, id

### Batch Operations

Process multiple operations efficiently with controlled parallelism.

#### Batch Parameters
```typescript
interface BatchOperationParams {
  batch_size?: number;        // Items per batch (default: 25, max: 100)
  max_parallel?: number;      // Parallel batches (default: 3, max: 10)
  continue_on_error?: boolean; // Continue on errors (default: true)
}
```

### Similarity Detection

Advanced content similarity detection with configurable thresholds and auto-update logic.

#### Similarity Features
- **Content hashing**: SHA-256 for exact duplicate detection
- **Trigram similarity**: PostgreSQL trigram for fuzzy matching
- **Branch-aware**: Only compares items within same scope
- **Auto-update**: Updates existing items instead of creating duplicates
- **Contradiction checking**: Identifies conflicting information

### Scope and Branch Isolation

Consistent isolation of knowledge by project, branch, and organization.

#### Scope Format
```typescript
interface QueryScope {
  project?: string;    // Project name
  branch?: string;     // Git branch
  org?: string;        // Organization
  [key: string]: unknown;
}
```

#### Isolation Features
- **Default scoping**: All operations respect project/branch boundaries
- **Cross-branch search**: Optional search across branches
- **Consistent enforcement**: All services use same scope logic
- **Security**: Prevents data leakage between projects

## Error Handling

### Error Categories

#### Validation Errors (400)
- `VALIDATION_FAILED`: General validation failure
- `INVALID_INPUT`: Invalid input provided
- `MISSING_REQUIRED_FIELD`: Required field is missing
- `INVALID_SCOPE`: Invalid scope parameters
- `INVALID_QUERY`: Invalid search query

#### Authorization Errors (401/403)
- `UNAUTHORIZED`: Authentication required
- `FORBIDDEN`: Access forbidden
- `SCOPE_VIOLATION`: Scope access violation

#### Not Found Errors (404)
- `NOT_FOUND`: Resource not found
- `ENTITY_NOT_FOUND`: Entity not found
- `KNOWLEDGE_TYPE_NOT_FOUND`: Knowledge type not supported

#### Conflict Errors (409)
- `DUPLICATE_ENTITY`: Duplicate entity detected
- `CONCURRENT_MODIFICATION`: Concurrent modification detected
- `CONSTRAINT_VIOLATION`: Constraint violation detected

#### Immutability Errors (422)
- `IMMUTABLE_ENTITY`: Cannot modify immutable entity
- `PROTECTED_OPERATION`: Operation not allowed on protected entity

#### Database Errors (500)
- `DATABASE_ERROR`: Database operation failed
- `CONNECTION_FAILED`: Database connection failed
- `TRANSACTION_FAILED`: Transaction failed
- `MIGRATION_FAILED`: Database migration failed

#### System Errors (500)
- `INTERNAL_ERROR`: Internal server error
- `PROCESSING_ERROR`: Processing operation failed
- `TIMEOUT_ERROR`: Operation timed out
- `RATE_LIMIT_EXCEEDED`: Rate limit exceeded
- `BATCH_OPERATION_FAILED`: Batch operation failed

### Error Response Format

```typescript
interface ErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    timestamp: string;
    request_id?: string;
    context?: {
      operation?: string;
      knowledge_type?: string;
      entity_id?: string;
      scope?: Record<string, unknown>;
    };
    details?: Record<string, unknown>;
  };
  metadata: {
    timestamp: string;
    request_id?: string;
    correlation_id?: string;
    operation: string;
    duration_ms?: number;
  };
}
```

## Observability

### Correlation IDs

All operations support comprehensive correlation tracking for distributed tracing.

#### Correlation Context
```typescript
interface CorrelationContext {
  correlation_id: string;    // Unique correlation identifier
  request_id: string;        // Unique request identifier
  trace_id?: string;         // Distributed trace ID
  parent_span_id?: string;   // Parent span for nesting
  span_id?: string;          // Current span ID
  operation: string;         // Operation name
  user_id?: string;          // User identifier
  session_id?: string;       // Session identifier
  client_info?: {
    ip_address?: string;
    user_agent?: string;
    platform?: string;
  };
  metadata?: Record<string, unknown>;
}
```

### Structured Logging

Comprehensive structured logging with performance monitoring.

#### Log Entry Structure
```typescript
interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  correlation: CorrelationContext;
  operation?: string;
  span?: SpanContext;
  performance?: {
    duration_ms?: number;
    memory_usage_mb?: number;
    cpu_usage_percent?: number;
  };
  error?: {
    name?: string;
    message?: string;
    stack?: string;
    code?: string;
    details?: Record<string, unknown>;
  };
  data?: Record<string, unknown>;
  tags?: Record<string, string>;
  service: {
    name: string;
    version: string;
    environment: string;
  };
  host?: {
    hostname: string;
    pid: number;
    platform: string;
  };
}
```

#### Performance Monitoring
- **Operation timing**: Detailed timing for all phases
- **Memory usage**: Heap usage tracking
- **Span management**: Distributed tracing support
- **Performance alerts**: Automatic detection of slow operations

### Monitoring Integration

The system integrates with standard monitoring tools:

- **Metrics**: Prometheus-compatible metrics
- **Tracing**: OpenTelemetry support
- **Logging**: JSON structured logs
- **Health checks**: Service health endpoints

## Performance Considerations

### Optimization Features

#### Auto-Maintenance
- **Purge thresholds**: Automatic cleanup of old data
- **Index optimization**: Query performance optimization
- **Statistics updates**: Automatic statistics refresh

#### Query Optimization
- **FTS optimization**: Full-text search optimization
- **Connection pooling**: Database connection management
- **Query caching**: Frequently used query caching
- **Batch processing**: Efficient bulk operations

#### Performance Targets
- **Store operations**: < 100ms for single items
- **Find operations**: < 200ms for typical queries
- **Delete operations**: < 50ms for soft deletes
- **Memory usage**: < 512MB for normal operations

### Scalability

#### Horizontal Scaling
- **Stateless design**: Services are stateless
- **Database sharding**: Support for read replicas
- **Caching layers**: Redis integration support
- **Load balancing**: Application agnostic

#### Vertical Scaling
- **Memory optimization**: Efficient memory usage
- **CPU optimization**: Async operations
- **I/O optimization**: Batch database operations
- **Connection management**: Connection pooling

## Migration Guide

### Database Migration

The system includes comprehensive database migrations:

```sql
-- Migration: 20241020_complete_fixes_migration.sql
-- Features:
-- 1. Missing tables for all knowledge types
-- 2. Server-managed fields (created_by, updated_by, request_id)
-- 3. Enhanced indexes for performance
-- 4. Triggers for data consistency
-- 5. Stored procedures for complex operations
-- 6. Auto-maintenance functions
-- 7. Data cleanup utilities
```

### Data Migration

#### Content Migration
- **Legacy data**: Support for importing existing data
- **Format conversion**: Automatic format normalization
- **Validation**: Data validation during migration
- **Rollback**: Migration rollback support

#### Schema Evolution
- **Backward compatibility**: Maintains compatibility
- **Graceful degradation**: Handles schema changes
- **Version management**: Schema version tracking
- **Migration scripts**: Automated migration support

## Testing

### Test Framework

The system includes comprehensive testing support:

#### Unit Tests
- **Service tests**: Individual service testing
- **Utility tests**: Helper function testing
- **Validation tests**: Schema validation testing
- **Error handling tests**: Error scenario testing

#### Integration Tests
- **Database tests**: Database integration testing
- **API tests**: End-to-end API testing
- **Performance tests**: Load and stress testing
- **Security tests**: Security vulnerability testing

#### Test Categories

**Functional Tests**
```typescript
describe('Memory Store', () => {
  it('should store a section with valid data', async () => {
    const response = await memory_store({
      items: [{
        kind: 'section',
        scope: { project: 'test' },
        data: {
          title: 'Test Section',
          heading: 'Test Section',
          body_md: '# Test Content',
        },
      }],
    });

    expect(response.stored).toHaveLength(1);
    expect(response.errors).toHaveLength(0);
  });
});
```

**Performance Tests**
```typescript
describe('Performance', () => {
  it('should complete store operation within 100ms', async () => {
    const start = Date.now();
    await memory_store({
      items: [testItem],
    });
    const duration = Date.now() - start;
    expect(duration).toBeLessThan(100);
  });
});
```

**Error Handling Tests**
```typescript
describe('Error Handling', () => {
  it('should handle invalid data gracefully', async () => {
    const response = await memory_store({
      items: [{
        kind: 'section',
        scope: { project: 'test' },
        data: {}, // Invalid: missing required fields
      }],
    });

    expect(response.errors).toHaveLength(1);
    expect(response.errors[0].error_code).toBe('VALIDATION_FAILED');
  });
});
```

### Test Utilities

#### Test Data Factory
```typescript
export class TestDataFactory {
  static createSection(overrides: Partial<SectionData> = {}): EnhancedKnowledgeItem {
    return {
      kind: 'section',
      scope: { project: 'test', branch: 'main' },
      data: {
        title: 'Test Section',
        heading: 'Test Section',
        body_md: '# Test Content',
        ...overrides,
      },
    };
  }

  static createDecision(overrides: Partial<DecisionData> = {}): EnhancedKnowledgeItem {
    return {
      kind: 'decision',
      scope: { project: 'test', branch: 'main' },
      data: {
        title: 'Test Decision',
        component: 'test',
        status: 'proposed',
        rationale: 'Test rationale',
        alternatives_considered: ['Alternative 1'],
        ...overrides,
      },
    };
  }
}
```

#### Database Test Helper
```typescript
export class DatabaseTestHelper {
  static async setupTestDatabase(): Promise<Pool> {
    // Create isolated test database
    // Run migrations
    // Return test pool
  }

  static async cleanupTestDatabase(pool: Pool): Promise<void> {
    // Clean up test data
    // Close connections
  }

  static async seedTestData(pool: Pool, data: TestData[]): Promise<void> {
    // Insert test data
    // Set up test scenarios
  }
}
```

## API Reference

### Knowledge Type Schemas

#### Section
```typescript
interface SectionData {
  id?: string;
  title: string;
  heading?: string;
  body_md?: string;
  body_text?: string;
  tags?: Record<string, unknown>;
}
```

#### Decision
```typescript
interface DecisionData {
  id?: string;
  component: string;
  status: 'proposed' | 'accepted' | 'deprecated' | 'superseded';
  title: string;
  rationale: string;
  alternatives_considered?: string[];
  consequences?: string;
  supersedes?: string;
}
```

#### Issue
```typescript
interface IssueData {
  id?: string;
  title: string;
  description: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  status?: 'open' | 'in_progress' | 'resolved' | 'closed';
  assignee?: string;
  labels?: string[];
}
```

#### TODO
```typescript
interface TodoData {
  id?: string;
  text: string;
  status?: 'pending' | 'in_progress' | 'completed' | 'cancelled';
  priority?: 'low' | 'medium' | 'high' | 'critical';
  assignee?: string;
  due_date?: string;
}
```

### Service Endpoints

#### Memory Store
- **Endpoint**: `memory_store`
- **Method**: Store knowledge items
- **Authentication**: Optional
- **Rate Limiting**: 100 requests/minute

#### Memory Find
- **Endpoint**: `memory_find`
- **Method**: Search knowledge items
- **Authentication**: Optional
- **Rate Limiting**: 200 requests/minute

#### Soft Delete
- **Endpoint**: `soft_delete`
- **Method**: Delete knowledge items
- **Authentication**: Required for deletions
- **Rate Limiting**: 50 requests/minute

## Configuration

### Environment Variables

```bash
# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/cortex_memory
DATABASE_POOL_SIZE=10
DATABASE_CONNECTION_TIMEOUT=30000

# Service Configuration
NODE_ENV=development
PORT=3000
LOG_LEVEL=info

# Observability Configuration
ENABLE_CORRELATION_LOGGING=true
ENABLE_PERFORMANCE_LOGGING=true
JAEGER_ENDPOINT=http://localhost:14268/api/traces

# Performance Configuration
MAX_PAGINATION_LIMIT=1000
DEFAULT_BATCH_SIZE=25
ENABLE_QUERY_CACHE=true

# Security Configuration
ENABLE_AUTHENTICATION=false
CORS_ORIGIN=http://localhost:3000
```

### Service Configuration

```typescript
interface ServiceConfig {
  database: {
    url: string;
    poolSize: number;
    connectionTimeout: number;
  };
  service: {
    name: string;
    version: string;
    environment: string;
  };
  logging: {
    level: LogLevel;
    format: 'json' | 'pretty';
    outputs: Array<'console' | 'file'>;
    enablePerformanceLogging: boolean;
    enableCorrelationLogging: boolean;
  };
  performance: {
    maxPaginationLimit: number;
    defaultBatchSize: number;
    enableQueryCache: boolean;
  };
  security: {
    enableAuthentication: boolean;
    corsOrigin: string;
  };
}
```

## Troubleshooting

### Common Issues

#### Performance Issues
- **Slow queries**: Check database indexes and query plans
- **Memory leaks**: Monitor memory usage patterns
- **Connection exhaustion**: Review connection pool settings

#### Data Issues
- **Duplicate entries**: Check idempotency_key handling
- **Missing data**: Verify scope conditions and filters
- **Inconsistent results**: Review similarity thresholds

#### Integration Issues
- **Connection failures**: Verify database connectivity
- **Authentication errors**: Check credential configuration
- **CORS issues**: Verify origin configuration

### Debugging Tools

#### Logging
- **Structured logs**: JSON format with correlation IDs
- **Performance logs**: Operation timing and memory usage
- **Error logs**: Detailed error context and stack traces

#### Monitoring
- **Health checks**: Service health status
- **Metrics**: Performance and usage metrics
- **Tracing**: Distributed request tracing

#### Diagnostics
- **Query analysis**: Database query performance
- **Memory profiling**: Heap usage analysis
- **Connection monitoring**: Database connection status

---

## Version History

### v1.0.0 (Current)
- Complete implementation of all 16 knowledge types
- Comprehensive search with query enhancement
- Pagination and sorting support
- Batch operations
- Correlation and structured logging
- Performance monitoring
- Comprehensive error handling
- Database migration support

### v0.9.0 (Previous)
- Basic knowledge management
- Simple search functionality
- Limited error handling

---

*This documentation covers the complete API surface of the Cortex Memory MCP system. For specific implementation details or advanced use cases, refer to the source code and inline documentation.*