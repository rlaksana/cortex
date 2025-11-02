# Knowledge Services Analysis for Test Coverage Improvement

## Executive Summary

Analysis of the top 5 knowledge services in mcp-cortex project to create comprehensive test coverage plan targeting 1000+ lines of test code to increase coverage from 47% to 80%+.

## Services Analyzed

### 1. Entity Service (src/services/knowledge/entity.ts)

**Purpose**: Flexible entity storage with dynamic schemas
**Key Methods**:

- `storeEntity(data, scope): Promise<string>` - Content-hash based deduplication
- `softDeleteEntity(id): Promise<boolean>` - Soft delete with timestamp
- `getEntity(id, scope?): Promise<EntityItem | null>` - Retrieve with optional scope filtering
- `searchEntities(query, filters): Promise<EntityItem[]>` - Full-text search with Qdrant

**Dependencies**:

- UnifiedDatabaseLayer v2
- crypto for content hashing
- Qdrant for full-text search

**Business Logic Patterns**:

- Content-hash deduplication prevents duplicates
- Soft delete pattern for data retention
- Scope-based isolation for multi-tenancy
- Flexible JSONB schema (no validation)

**Testing Opportunities**:

- Content hash generation and collision scenarios
- Scope filtering edge cases
- Full-text search with special characters
- Soft delete cascades
- Database error handling

### 2. Decision Service (src/services/knowledge/decision.ts)

**Purpose**: Architecture Decision Record (ADR) management
**Key Methods**:

- `storeDecision(data, scope): Promise<string>` - Create new ADR
- `updateDecision(id, data): Promise<void>` - Update with immutability checks

**Dependencies**:

- UnifiedDatabaseLayer v2
- Qdrant client for direct access
- Immutability validator

**Business Logic Patterns**:

- ADR immutability (accepted decisions cannot be modified)
- Scope-based organization
- Alternatives considered tracking

**Testing Opportunities**:

- Immutability violation scenarios
- Status transition validation
- Alternative handling edge cases
- Scope isolation testing

### 3. Todo Service (src/services/knowledge/todo.ts)

**Purpose**: Task and todo management
**Key Methods**:

- `storeTodo(data, scope): Promise<string>` - Create new todo
- `updateTodo(id, data, scope): Promise<string>` - Update existing todo

**Dependencies**:

- UnifiedDatabaseLayer v2
- Date handling for due dates

**Business Logic Patterns**:

- Status-based workflow management
- Priority handling
- Assignee tracking
- Due date management

**Testing Opportunities**:

- Status transition validation
- Due date boundary testing
- Priority ordering
- Scope merging behavior
- Not found error handling

### 4. Issue Service (src/services/knowledge/issue.ts)

**Purpose**: Issue tracking with external system integration
**Key Methods**:

- `validateQdrantSchemaCompliance(data): void` - Schema validation
- `storeIssue(data, scope): Promise<string>` - Create new issue

**Dependencies**:

- UnifiedDatabaseLayer v2
- Qdrant client for direct access
- Schema validation logic

**Business Logic Patterns**:

- Schema compliance enforcement
- External system integration (tracker, external_id)
- Label and metadata handling
- URL tracking

**Testing Opportunities**:

- Schema violation scenarios
- Field length validation
- External ID uniqueness
- Label serialization/deserialization
- Metadata vs direct field access

### 5. Observation Service (src/services/knowledge/observation.ts)

**Purpose**: Fine-grained fact storage with append-only pattern
**Key Methods**:

- `addObservation(data, scope?): Promise<string>` - Add observation
- `deleteObservation(id): Promise<boolean>` - Soft delete
- `deleteObservationsByText(entity_type, entity_id, text): Promise<number>` - Bulk delete
- `getObservations(entity_type, entity_id, filter?): Promise<Array>` - Retrieve observations
- `searchObservations(query, filter?, limit?): Promise<Array>` - FTS and LIKE search
- `getObservationCount(entity_type, entity_id): Promise<number>` - Count observations
- `getRecentObservations(limit?, filter?): Promise<Array>` - Recent activity feed

**Dependencies**:

- UnifiedDatabaseLayer (v1 - inconsistent)
- Qdrant client for raw queries
- Full-text search capabilities

**Business Logic Patterns**:

- Append-only storage pattern
- Soft delete lifecycle management
- Full-text search with tsquery
- Entity relationship tracking
- Activity feed generation

**Critical Issues Found**:

- Import inconsistency (UnifiedDatabaseLayer v1 vs v2)
- Direct qdrant usage without proper initialization
- Complex raw SQL queries with potential injection risks
- Inconsistent error handling patterns

## Current Test Coverage Analysis

- Existing tests focus on integration scenarios
- Limited unit test coverage for edge cases
- Missing comprehensive error handling tests
- No performance testing for search operations
- Limited testing of database constraint violations

## Recommended Testing Strategy

1. **Unit Tests**: Individual method testing with mocks
2. **Integration Tests**: Database interaction testing
3. **Error Scenarios**: Database failures, constraint violations
4. **Performance Tests**: Search operations, large datasets
5. **Security Tests**: SQL injection, scope isolation
6. **Edge Cases**: Boundary conditions, data type extremes

## Estimated Test Coverage Impact

- Target: 1000+ lines of test code
- Expected coverage increase: 47% → 80%+
- Focus on critical business logic and error paths
- Include performance and security testing
