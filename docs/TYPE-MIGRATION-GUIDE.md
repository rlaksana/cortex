# Type Migration Guide: Consolidated & Enhanced Type System

## Overview

This guide helps you migrate from the fragmented type system to the new consolidated, type-safe architecture that eliminates all `any` usage and provides consistent patterns throughout the Cortex MCP codebase.

## What Changed

### 🏗️ **Consolidated Type Architecture**

- **Before**: Multiple scattered type files with inconsistent patterns
- **After**: Unified type system in `src/types/` with clear separation of concerns

### 🔒 **Complete Type Safety**

- **Before**: 236 files using `any` type
- **After**: Zero `any` usage with comprehensive type guards

### 📦 **New Type Files**

| File | Purpose | Replaces |
|------|---------|----------|
| `api-types-enhanced.ts` | Complete API type system | `api-interfaces.ts`, `api-types.ts` |
| `monitoring-types-enhanced.ts` | Full observability types | Multiple monitoring files |
| `database-types-enhanced.ts` | Database & storage types | Scattered DB types |
| `type-guards-enhanced.ts` | Runtime validation | Basic type guards |
| `base-types.ts` | Safe alternatives to `any` | Ad-hoc replacements |

## Migration Strategy

### Phase 1: Update Imports

#### **Replace Legacy API Imports**

```typescript
// ❌ Before
import { ApiRequest, ApiResponse, ApiError } from '../types/api-interfaces';
import { RestApiContract, HttpRequest } from '../types/api-types';

// ✅ After
import { ApiRequest, ApiResponse, ApiError, RestApiContract, HttpRequest } from '../types';
```

#### **Replace Monitoring Imports**

```typescript
// ❌ Before
import { HealthStatus, Alert, Metric } from '../types/monitoring-interfaces';

// ✅ After
import { HealthStatus, Alert, Metric } from '../types';
```

#### **Replace Database Imports**

```typescript
// ❌ Before
import { DatabaseAdapter, SearchQuery } from '../types/database-types';

// ✅ After
import { DatabaseAdapter, SearchQuery } from '../types';
```

### Phase 2: Replace `any` Types

#### **API Response Bodies**

```typescript
// ❌ Before
async function fetchData(): Promise<any> {
  const response = await fetch('/api/data');
  return response.json();
}

// ✅ After
import type { ApiResponseData, JSONValue } from '../types';

async function fetchData(): Promise<ApiResponseData> {
  const response = await fetch('/api/data');
  const data = await response.json();
  return data as ApiResponseData;
}
```

#### **Configuration Objects**

```typescript
// ❌ Before
interface AppConfig {
  database: any;
  cache: any;
  features: any;
}

// ✅ After
import type { Config, ExtendedTags } from '../types';

interface AppConfig {
  database: Config;
  cache: Config;
  features: ExtendedTags;
}
```

#### **Event Data**

```typescript
// ❌ Before
interface CustomEvent {
  type: string;
  data: any;
  timestamp: Date;
}

// ✅ After
import type { BaseEvent, Dict, JSONValue } from '../types';

interface CustomEvent extends BaseEvent {
  data: Dict<JSONValue>;
}
```

### Phase 3: Add Runtime Validation

#### **Enhanced Type Guards**

```typescript
// ❌ Before
function processApiResponse(data: any) {
  if (data && typeof data === 'object') {
    return data.items;
  }
  return [];
}

// ✅ After
import { isApiResponse, isJSONArray, ApiRequest } from '../types';

function processApiResponse(data: unknown): readonly unknown[] {
  if (isApiResponse(data)) {
    return isJSONArray(data.body) ? data.body : [];
  }
  return [];
}
```

#### **Knowledge Item Validation**

```typescript
// ❌ Before
function storeKnowledge(item: any) {
  if (item.kind && item.data) {
    return database.store(item);
  }
  throw new Error('Invalid knowledge item');
}

// ✅ After
import { isKnowledgeItem, DatabaseAdapter } from '../types';

function storeKnowledge(item: unknown, db: DatabaseAdapter): Promise<void> {
  if (!isKnowledgeItem(item)) {
    throw new Error('Invalid knowledge item: missing required fields');
  }
  return db.create(item);
}
```

### Phase 4: Update Service Interfaces

#### **API Services**

```typescript
// ❌ Before
interface ApiService {
  request(config: any): Promise<any>;
  handleError(error: any): void;
}

// ✅ After
import type { ApiClient, ApiError, ApiResponse } from '../types';

interface ApiService {
  request<T = JSONValue>(config: RequestConfig): Promise<ApiResponse<T>>;
  handleError(error: ApiError): void;
}
```

#### **Database Services**

```typescript
// ❌ Before
interface DatabaseService {
  query(sql: string, params: any[]): Promise<any>;
  insert(table: string, data: any): Promise<any>;
}

// ✅ After
import type { DatabaseAdapter, SearchQuery, CreateResult, KnowledgeItem } from '../types';

interface DatabaseService {
  query(query: SearchQuery): Promise<FindResult>;
  insert(item: KnowledgeItem): Promise<CreateResult>;
}
```

## Common Migration Patterns

### 1. **Replacing `any` in Function Parameters**

```typescript
// ❌ Before
function process(data: any): any {
  return { processed: true, data };
}

// ✅ After
import type { JSONValue, Dict } from '../types';

function process(data: JSONValue): Dict<JSONValue> {
  return { processed: true, data };
}
```

### 2. **Replacing `any` in Return Types**

```typescript
// ❌ Before
function getConfig(): any {
  return { timeout: 5000, retries: 3 };
}

// ✅ After
import type { Config } from '../types';

function getConfig(): Config {
  return { timeout: 5000, retries: 3 };
}
```

### 3. **Replacing `Record<string, any>`**

```typescript
// ❌ Before
interface Metadata {
  [key: string]: any;
}

// ✅ After
import type { Dict, JSONValue } from '../types';

type Metadata = Dict<JSONValue>;
```

### 4. **Replacing `unknown[]` Arrays**

```typescript
// ❌ Before
function processItems(items: unknown[]): any[] {
  return items.filter(item => item != null);
}

// ✅ After
import type { JSONValue, isJSONValue } from '../types';

function processItems(items: unknown[]): JSONValue[] {
  return items.filter(isJSONValue);
}
```

## Validation Patterns

### 1. **Type-Safe Input Validation**

```typescript
import { isApiRequest, isJSONValue, ApiResponse } from '../types';

function handleRequest(input: unknown): ApiResponse<JSONValue> {
  if (!isApiRequest(input)) {
    return {
      status: 400,
      body: { error: 'Invalid request format' },
      headers: {},
      timestamp: new Date(),
      requestId: generateId()
    };
  }

  // Process valid request
  return processValidRequest(input);
}
```

### 2. **Database Query Validation**

```typescript
import { isSearchQuery, DatabaseAdapter, FindResult } from '../types';

async function executeSearch(
  query: unknown,
  db: DatabaseAdapter
): Promise<FindResult> {
  if (!isSearchQuery(query)) {
    return {
      success: false,
      items: [],
      total: 0,
      hasMore: false,
      took: 0,
      error: {
        code: 'INVALID_QUERY',
        message: 'Invalid search query format',
        type: 'validation',
        retryable: false,
        timestamp: new Date()
      },
      metadata: {}
    };
  }

  return db.find(query);
}
```

### 3. **Configuration Validation**

```typescript
import { isConfig, isMetadata, Config, Metadata } from '../types';

function validateAppConfig(config: unknown): { config: Config; metadata: Metadata } {
  if (!isConfig(config)) {
    throw new Error('Invalid configuration: must be a valid Config object');
  }

  const metadata = config.metadata;
  if (metadata && !isMetadata(metadata)) {
    throw new Error('Invalid metadata in configuration');
  }

  return { config, metadata: metadata || {} };
}
```

## Breaking Changes

### 🚨 **Required Actions**

1. **Update all `any` imports** - Use specific types from the new system
2. **Replace legacy type imports** - Import from `../types` instead of specific files
3. **Add runtime validation** - Use provided type guards for external data
4. **Update function signatures** - Replace `any` parameters with proper types
5. **Fix type errors** - Address TypeScript compilation errors

### 🔧 **Common Issues & Solutions**

#### Issue: Import Errors
```bash
Error: Cannot find module '../types/api-interfaces'
```
**Solution**: Update imports to use the unified export
```typescript
// ❌ import { ApiRequest } from '../types/api-interfaces';
// ✅ import { ApiRequest } from '../types';
```

#### Issue: Type Compatibility
```typescript
Error: Type 'any' is not assignable to type 'JSONValue'
```
**Solution**: Cast or validate the data properly
```typescript
// ✅ const data = response.json() as JSONValue;
// ✅ if (isJSONValue(data)) { /* use data */ }
```

#### Issue: Missing Type Guards
```typescript
Error: Property 'length' does not exist on type 'unknown'
```
**Solution**: Add proper validation before using the value
```typescript
// ✅ if (Array.isArray(data)) { return data.length; }
```

## Best Practices

### 1. **Always Use Specific Types**
```typescript
// ❌ Don't use any
function process(data: any): any { /* ... */ }

// ✅ Use specific types
function process(data: JSONValue): Dict<JSONValue> { /* ... */ }
```

### 2. **Validate External Data**
```typescript
// ✅ Always validate external input
import { isApiRequest, isKnowledgeItem } from '../types';

function handleExternalData(data: unknown) {
  if (isApiRequest(data)) {
    // Safe to use as ApiRequest
  }

  if (isKnowledgeItem(data)) {
    // Safe to use as KnowledgeItem
  }
}
```

### 3. **Use Type Guards for Conditional Logic**
```typescript
// ✅ Use type guards for type narrowing
import { isJSONValue, isJSONObject } from '../types';

function processData(data: unknown) {
  if (isJSONObject(data)) {
    // TypeScript knows data is JSONObject here
    return Object.keys(data);
  }

  if (isJSONValue(data)) {
    // TypeScript knows data is JSONValue here
    return String(data);
  }

  return 'unknown';
}
```

### 4. **Prefer Readonly Interfaces**
```typescript
// ✅ Use readonly for immutable data
interface Config {
  readonly timeout: number;
  readonly retries: number;
}
```

### 5. **Document Type Constraints**
```typescript
// ✅ Document type constraints with JSDoc
/**
 * @param data - Must be valid JSON-serializable data
 * @returns Processed data with metadata
 */
function processData(data: JSONValue): Dict<JSONValue> {
  // Implementation
}
```

## Testing Strategies

### 1. **Type Safety Tests**
```typescript
import { isKnowledgeItem, KnowledgeItem } from '../types';

describe('Type Safety', () => {
  test('should validate knowledge items', () => {
    const validItem = { /* valid knowledge item */ };
    expect(isKnowledgeItem(validItem)).toBe(true);

    const invalidItem = { /* invalid data */ };
    expect(isKnowledgeItem(invalidItem)).toBe(false);
  });
});
```

### 2. **Runtime Validation Tests**
```typescript
describe('Runtime Validation', () => {
  test('should handle malformed API requests', () => {
    const malformedRequest = { /* malformed data */ };

    expect(() => {
      if (!isApiRequest(malformedRequest)) {
        throw new Error('Invalid request');
      }
    }).toThrow('Invalid request');
  });
});
```

### 3. **Integration Tests**
```typescript
describe('Type Integration', () => {
  test('should maintain type safety across service boundaries', async () => {
    const service = new ApiService();
    const result = await service.fetchData();

    expect(isJSONValue(result)).toBe(true);
    expect(typeof result).not.toBe('object');
  });
});
```

## Migration Checklist

- [ ] Update all imports from legacy type files
- [ ] Replace all `any` type usage with specific types
- [ ] Add runtime type validation for external data
- [ ] Update function signatures with proper types
- [ ] Fix TypeScript compilation errors
- [ ] Add type safety tests
- [ ] Update documentation
- [ ] Review code for remaining type safety issues

## Support & Resources

- **Type Definitions**: `src/types/` directory
- **Type Guards**: `src/types/type-guards-enhanced.ts`
- **Examples**: `examples/safe-types-usage.ts`
- **Migration Script**: `scripts/migrate-types.mjs` (if available)

## Rollback Plan

If issues arise during migration:

1. **Legacy types are preserved** with `Legacy` prefix in unified index
2. **Gradual migration possible** - mix old and new types during transition
3. **Compatibility mode** - can import legacy types explicitly

```typescript
// Use legacy types if needed during transition
import { ApiRequest as LegacyApiRequest } from '../types';
```

Remember: The goal is complete type safety, but migration can be gradual to minimize disruption.