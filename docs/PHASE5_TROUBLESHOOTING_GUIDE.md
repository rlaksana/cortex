# Phase 5 Validation & Metrics - Troubleshooting Guide

## Overview

This guide addresses common issues encountered during Phase 5 validation and provides step-by-step solutions for resolving TypeScript compilation errors, type system issues, and build problems.

## Common TypeScript Compilation Errors

### Error: "Property 'x' is missing in type 'Y' but required in type 'Z'"

**Cause:** Interface compatibility issues between old and new type systems
**Example:**
```
src/db/adapters/qdrant-adapter.ts(142,5): error TS2739: Type '{ vectorSize: number; distance: "Cosine" | "Euclidean" | "Dot" | "Manhattan"; logQueries: boolean; connectionTimeout: number; maxConnections: number; collectionName: string; apiKey?: string | undefined; type: "qdrant"; url: string; }' is missing the following properties from type 'VectorConfig': host, port, database
```

**Solution:**
1. Identify the missing properties from the error message
2. Add the missing properties to the configuration object
3. Use proper defaults for optional properties

```typescript
// Before
this.config = {
  type: 'qdrant',
  url: config.url || 'http://localhost:6333',
  vectorSize: config.vectorSize || 1536,
  // Missing: host, port, database
};

// After
this.config = {
  type: 'qdrant',
  host: config.host || 'localhost',
  port: config.port || 6333,
  database: config.database || 'qdrant',
  url: config.url || 'http://localhost:6333',
  vectorSize: config.vectorSize || 1536,
};
```

### Error: "Type 'unknown' is not assignable to parameter of type 'string'"

**Cause:** Type safety issues with unknown data types
**Example:**
```
src/constants/kind-validation-features.ts(114,35): error TS2345: Argument of type 'unknown' is not assignable to parameter of type '"entity" | "relation" | "observation" | "section" | "runbook" | "change" | "issue" | "decision" | "todo" | "release_note" | "ddl" | "pr_context" | "incident" | "release" | "risk" | "assumption"'.
```

**Solution:**
1. Add proper type assertions or type guards
2. Use explicit type checking before assignment

```typescript
// Before
return SUPPORTED_KINDS.includes(kind as unknown);

// After
return SUPPORTED_KINDS.includes(kind as (typeof SUPPORTED_KINDS)[number]);

// Or with type guard
function isSupportedKind(kind: string): kind is (typeof SUPPORTED_KINDS)[number] {
  return SUPPORTED_KINDS.includes(kind as (typeof SUPPORTED_KINDS)[number]);
}
```

### Error: "Property 'x' is possibly 'undefined'"

**Cause:** TypeScript strict null checking
**Example:**
```
src/db/adapters/qdrant-adapter.ts(431,23): error TS18048: 'existingPoint.id.num' is possibly 'undefined'.
```

**Solution:**
1. Add null/undefined checks
2. Use optional chaining or nullish coalescing

```typescript
// Before
const pointId = existingPoint.id.num;

// After
const pointId = existingPoint.id.num ?? existingPoint.id.uuid ?? existingPoint.id.str;
```

### Error: "Argument of type 'A' is not assignable to parameter of type 'B'"

**Cause:** Interface signature mismatches
**Example:**
```
src/db/adapters/qdrant-adapter.ts(397,9): error TS2416: Property 'store' in type 'QdrantAdapter' is not assignable to the same property in base type 'IVectorAdapter<unknown, VectorConfig>'.
```

**Solution:**
1. Update method signatures to match interface requirements
2. Implement DatabaseResult wrapper pattern

```typescript
// Before
async store(items: KnowledgeItem[], options?: StoreOptions): Promise<MemoryStoreResponse> {
  // Implementation
  return response;
}

// After
async store(items: readonly KnowledgeItem[], options?: StoreOptions = {}): Promise<DatabaseResult<MemoryStoreResponse>> {
  return this.wrapAsyncOperation(async () => {
    // Implementation
    return response;
  }, 'store');
}
```

## Build and Dependency Issues

### Issue: Module Resolution Failures

**Symptoms:**
```
error TS2307: Cannot find module './module-name' or its corresponding type declarations.
```

**Solutions:**
1. Check file paths and extensions
2. Verify import/export statements
3. Ensure proper module resolution configuration

```bash
# Check if file exists
ls -la src/path/to/module.ts

# Verify tsconfig.json paths configuration
cat tsconfig.json | grep -A 10 "paths"
```

### Issue: Circular Dependencies

**Symptoms:**
```
error TS2440: Import declaration conflicts with local declaration of 'TypeName'.
```

**Solutions:**
1. Identify circular import patterns
2. Refactor to remove circular dependencies
3. Use proper dependency injection

```typescript
// Before (circular)
// fileA.ts imports from fileB.ts
// fileB.ts imports from fileA.ts

// After (resolve circular)
// Create shared types file
// file-types.ts - shared type definitions
// fileA.ts imports from file-types.ts
// fileB.ts imports from file-types.ts
```

## ESLint and Formatting Issues

### Issue: Import Sorting Errors

**Symptoms:**
```
warning  Run autofix to sort these imports!  simple-import-sort/imports
```

**Solutions:**
1. Run automatic fix
2. Manually organize imports if needed

```bash
# Auto-fix import sorting
npm run lint:fix

# Manual import organization
# 1. External libraries
// import external libraries here

// 2. Internal modules (absolute)
// import @/path/to/module

// 3. Relative imports
// import ./relative/module
```

### Issue: Code Formatting Inconsistencies

**Symptoms:**
```
warning  Code style issues detected
```

**Solutions:**
1. Run Prettier formatting
2. Configure editor format-on-save

```bash
# Format all files
npm run format

# Check formatting issues
npm run format:check
```

## Performance Issues

### Issue: Slow Build Times

**Symptoms:**
- Build taking > 30 seconds
- Memory usage spikes during compilation

**Solutions:**
1. Optimize TypeScript configuration
2. Use incremental compilation
3. Exclude unnecessary files

```json
// tsconfig.json
{
  "compilerOptions": {
    "incremental": true,
    "tsBuildInfoFile": ".tsbuildinfo"
  },
  "exclude": [
    "node_modules",
    "dist",
    "**/*.test.ts",
    "**/*.spec.ts"
  ]
}
```

### Issue: Memory Usage During Build

**Symptoms:**
- Out of memory errors during compilation
- High RAM usage

**Solutions:**
1. Increase Node.js memory limit
2. Use incremental compilation
3. Split large files

```bash
# Increase Node.js memory limit
export NODE_OPTIONS="--max-old-space-size=4096"
npm run build

# Or in package.json scripts
"build": "NODE_OPTIONS='--max-old-space-size=4096' tsc"
```

## Testing and Validation Issues

### Issue: Test Failures After Type Migration

**Symptoms:**
- Tests failing due to type changes
- Mock objects not matching new interfaces

**Solutions:**
1. Update test mocks to match new interfaces
2. Use proper typing in test files
3. Add type assertions where needed

```typescript
// Before
const mockAdapter = {
  store: jest.fn().mockResolvedValue({ items: [] })
};

// After
const mockAdapter = {
  store: jest.fn().mockResolvedValue({
    success: true,
    data: { items: [] }
  })
};
```

### Issue: Integration Test Failures

**Symptoms:**
- Integration tests failing after type changes
- Database connection issues

**Solutions:**
1. Update integration test setup
2. Ensure test configuration matches new interfaces
3. Mock external dependencies properly

```typescript
// Update test configuration to use new interface
const testConfig: VectorConfig = {
  type: 'qdrant',
  host: 'localhost',
  port: 6333,
  database: 'test_db',
  url: 'http://localhost:6333'
};
```

## Debugging Techniques

### 1. Incremental Error Resolution

**Approach:** Fix errors one by one, starting with the most critical

```bash
# Fix errors in specific file
npx tsc --noEmit src/file-with-errors.ts

# Get detailed error information
npx tsc --noEmit --pretty false src/file-with-errors.ts
```

### 2. Type Investigation

**Approach:** Use TypeScript to understand type relationships

```typescript
// Add type debug logs
console.log(typeof variable);
console.log(variable as any); // Force display

// Use type assertions for investigation
const debugVar = variable as ExpectedType;
```

### 3. Build Analysis

**Approach:** Analyze build performance and bottlenecks

```bash
# Build with detailed timing
npm run build -- --timing

# Analyze build output
find dist -name "*.js" | xargs wc -l | sort -nr
```

## Recovery Procedures

### Partial Build Recovery

**When:** Some files compile but others don't

```bash
# Build specific files
npx tsc src/working-file.ts --noEmit

# Skip problematic files temporarily
npx tsc --skipLibCheck --noEmit
```

### Rollback Strategies

**When:** Changes break the build completely

```bash
# Reset to last working state
git reset --hard HEAD~1

# Stash changes and reset
git stash
git reset --hard origin/main
```

### Alternative Compilation Strategies

**When:** Standard compilation fails

```bash
# Use alternative tsconfig
npx tsc --project tsconfig.base.json --noEmit

# Compile with different strictness level
npx tsc --strict false --noEmit
```

## Getting Help

### Internal Resources
- [Type System Migration Guide](TYPE_SYSTEM_MIGRATION_GUIDE.md)
- [API Documentation](API-REFERENCE.md)
- [Development Setup Guide](SETUP-QUICK-START.md)

### External Resources
- [TypeScript Documentation](https://www.typescriptlang.org/docs/)
- [ESLint Rules Reference](https://eslint.org/docs/rules/)
- [Prettier Configuration](https://prettier.io/docs/en/options.html)

### Team Support
- Create GitHub issues for blockers
- Consult team leads for architectural decisions
- Use pair programming for complex issues

## Prevention Strategies

### 1. Automated Validation
```bash
# Add to CI/CD pipeline
npm run type-check
npm run lint
npm run format:check
```

### 2. Pre-commit Hooks
```json
// package.json
{
  "husky": {
    "hooks": {
      "pre-commit": "npm run type-check && npm run lint"
    }
  }
}
```

### 3. Development Guidelines
- Compile frequently during development
- Use TypeScript strict mode
- Keep type definitions up to date
- Regular code reviews focused on type safety