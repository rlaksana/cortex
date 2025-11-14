# Type System Migration Guide

## Overview

This guide provides comprehensive instructions for migrating the Cortex Memory MCP Server from the legacy type system to the enhanced, type-safe architecture. The migration addresses the 311 TypeScript compilation errors identified in Phase 5 validation.

## Migration Strategy

### Phase 1: Interface Standardization

#### 1.1 DatabaseResult Interface Adoption

**Current State:** Many methods return raw types instead of DatabaseResult wrapper
**Target:** All database operations return `DatabaseResult<T>` format

**Implementation:**
```typescript
// Before
async store(items: KnowledgeItem[]): Promise<MemoryStoreResponse> {
  // ... implementation
  return response;
}

// After
async store(items: readonly KnowledgeItem[], options?: StoreOptions): Promise<DatabaseResult<MemoryStoreResponse>> {
  return this.wrapAsyncOperation(async () => {
    // ... implementation
    return response;
  }, 'store');
}
```

**Required Changes:**
- [ ] Update `QdrantAdapter` method signatures
- [ ] Implement `DatabaseResult` wrapping utilities
- [ ] Update error handling to use DatabaseError
- [ ] Modify callers to handle DatabaseResult format

#### 1.2 PointId Type Standardization

**Current State:** Inconsistent use of string vs PointId types
**Target:** Consistent PointId usage throughout

**Implementation:**
```typescript
// Before
async delete(ids: string[]): Promise<{ deleted: number; errors: StoreError[] }> {
  // ... implementation
}

// After
async delete(ids: readonly PointId[], options?: DeleteOptions): Promise<DatabaseResult<{ deletedCount: number; errors: readonly StoreError[] }>> {
  return this.wrapAsyncOperation(async () => {
    const idStrings = ids.map(id => typeof id === 'string' ? id : String(id));
    // ... implementation with idStrings
  }, 'delete');
}
```

### Phase 2: Configuration Type Migration

#### 2.1 VectorConfig Interface Updates

**Current State:** Missing required properties in VectorConfig
**Target:** Complete VectorConfig with all required properties

**Implementation:**
```typescript
// Before
this.config = {
  type: 'qdrant',
  url: config.url || 'http://localhost:6333',
  // ... missing host, port, database
};

// After
this.config = {
  type: 'qdrant',
  host: config.host || 'localhost',
  port: config.port || 6333,
  database: config.database || 'qdrant',
  url: config.url || 'http://localhost:6333',
  // ... other properties
};
```

#### 2.2 Type Guard Enhancements

**Current State:** Basic type checking with unknown types
**Target:** Comprehensive type safety with proper guards

**Implementation:**
```typescript
// Before
if (item.data.expiry_at) {
  return item.data.expiry_at; // Type error: unknown
}

// After
if (item.data.expiry_at && typeof item.data.expiry_at === 'string') {
  return item.data.expiry_at;
}
```

### Phase 3: Error Handling Standardization

#### 3.1 DatabaseError Implementation

**Current State:** Inconsistent error types and handling
**Target:** Standardized DatabaseError with proper structure

**Implementation:**
```typescript
// Utility methods for consistent error handling
private createSuccessResult<T>(data: T, metadata?: Record<string, unknown>): DatabaseResult<T> {
  return { success: true, data, metadata };
}

private createErrorResult<T>(error: DatabaseError, metadata?: Record<string, unknown>): DatabaseResult<T> {
  return { success: false, error, metadata };
}

private async wrapAsyncOperation<T>(
  operation: () => Promise<T>,
  operationName: string
): Promise<DatabaseResult<T>> {
  try {
    const result = await operation();
    return this.createSuccessResult(result, { operation: operationName });
  } catch (error) {
    const dbError = error instanceof DatabaseError
      ? error
      : new DatabaseError(`Failed ${operationName}: ${error instanceof Error ? error.message : String(error)}`);
    return this.createErrorResult(dbError, { operation: operationName });
  }
}
```

## Step-by-Step Migration Plan

### Step 1: Database Layer (Highest Priority)

1. **Update QdrantAdapter**
   ```bash
   # Files to modify:
   - src/db/adapters/qdrant-adapter.ts
   - src/db/interfaces/vector-adapter.interface.ts
   ```

2. **Implement DatabaseResult Utilities**
   ```typescript
   // Add to each adapter class
   private createSuccessResult<T>(data: T): DatabaseResult<T>
   private createErrorResult<T>(error: DatabaseError): DatabaseResult<T>
   private async wrapAsyncOperation<T>(op: () => Promise<T>): Promise<DatabaseResult<T>>
   ```

3. **Update Method Signatures**
   ```typescript
   // Update all adapter methods to return DatabaseResult<T>
   async store(items: readonly KnowledgeItem[], options?: StoreOptions): Promise<DatabaseResult<MemoryStoreResponse>>
   async search(query: SearchQuery, options?: SearchOptions): Promise<DatabaseResult<MemoryFindResponse>>
   async delete(ids: readonly PointId[], options?: DeleteOptions): Promise<DatabaseResult<DeleteResult>>
   ```

### Step 2: Configuration Layer

1. **Fix VectorConfig Interface**
   ```typescript
   // Update src/db/interfaces/vector-adapter.interface.ts
   export interface VectorConfig extends VectorDatabaseConfig {
     // Ensure all required properties from VectorDatabaseConfig are included
     host: string;
     port: number;
     database: string;
     // ... other properties
   }
   ```

2. **Update Configuration Validators**
   ```typescript
   // Update src/config/configuration-validator.ts
   // Ensure proper type checking for all configuration properties
   ```

### Step 3: Type System Consolidation

1. **Resolve Circular Dependencies**
   ```typescript
   // Move type definitions to appropriate locations
   // Use proper import/export patterns
   // Avoid circular references
   ```

2. **Update Type Guards**
   ```typescript
   // Enhance src/utils/type-guards.ts
   // Add comprehensive type checking utilities
   // Remove unknown types where possible
   ```

## Validation Checklist

### Pre-Migration
- [ ] Backup current codebase
- [ ] Create feature branch for migration
- [ ] Set up automated testing
- [ ] Document current behavior

### During Migration
- [ ] Fix compilation errors incrementally
- [ ] Run tests after each change
- [ ] Validate functionality remains unchanged
- [ ] Update documentation

### Post-Migration
- [ ] Full test suite execution
- [ ] Performance regression testing
- [ ] Code review and validation
- [ ] Update API documentation

## Common Issues and Solutions

### Issue 1: DatabaseResult Interface Mismatch
**Problem:** Methods returning raw types instead of DatabaseResult
**Solution:** Implement wrapper utilities and update all method signatures

### Issue 2: PointId Type Inconsistency
**Problem:** Mixed usage of string and PointId types
**Solution:** Standardize on PointId with proper conversion utilities

### Issue 3: Configuration Type Safety
**Problem:** Missing required properties in configuration interfaces
**Solution:** Update interfaces to include all required properties

### Issue 4: Type Guard Completeness
**Problem:** Unknown types causing compilation errors
**Solution:** Implement comprehensive type checking with proper guards

## Rollback Plan

If migration encounters critical issues:

1. **Immediate Rollback**
   ```bash
   git revert <migration-commit>
   npm install
   npm run build  # Verify build succeeds
   ```

2. **Partial Rollback**
   ```bash
   # Revert specific files while keeping others
   git checkout HEAD~1 -- src/db/adapters/qdrant-adapter.ts
   ```

3. **Staged Rollback**
   ```bash
   # Keep working changes but revert to stable state
   git stash
   ```

## Success Criteria

### Compilation Success
- [ ] Zero TypeScript compilation errors
- [ ] All tests passing
- [ ] Build process completes successfully

### Type Safety
- [ ] No 'any' types in critical paths
- [ ] Comprehensive type guard coverage
- [ ] Interface compatibility maintained

### Functionality
- [ ] All features working as expected
- [ ] Performance benchmarks met
- [ ] API contracts maintained

## Resources

### Documentation
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [Database-Generic Types Reference](src/types/database-generics.ts)
- [API Documentation](docs/API-REFERENCE.md)

### Tools
- TypeScript compiler (`tsc`)
- ESLint with TypeScript rules
- Type testing utilities

### Support
- Create GitHub issues for migration blockers
- Consult team leads for architectural decisions
- Use feature flags for gradual rollout

## Timeline

**Estimated Effort:** 2-3 sprints
**Critical Path:** Database layer migration
**Dependencies:** Type system consolidation
**Risks:** Interface compatibility, breaking changes