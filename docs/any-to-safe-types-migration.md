# Migration Guide: From `any` to Safe Base Types

This guide provides comprehensive instructions for migrating from `any` usage to the new safe base types introduced in the Cortex MCP system.

## Overview

The migration introduces type-safe alternatives to common `any` patterns while maintaining flexibility and providing runtime validation capabilities.

## Quick Reference

| `any` Pattern | Safe Type | Type Guard | Use Case |
|---------------|-----------|------------|----------|
| `Record<string, any>` | `Dict<JSONValue>` | `isDict(value, isJSONValue)` | Generic key-value stores |
| `any` (JSON data) | `JSONValue` | `isJSONValue` | API responses, configuration |
| `any` (metadata) | `Metadata` | `isMetadata` | Entity metadata |
| `any` (tags) | `Tags` | `isTags` | Tagging systems |
| `any` (config) | `Config` | `isConfig` | Configuration objects |

## Migration Patterns

### 1. JSON Data and API Responses

#### Before:
```typescript
interface ApiResponse {
  data: any;
  metadata: Record<string, any>;
}

function processResponse(response: any) {
  return response.data.value;
}
```

#### After:
```typescript
import type { JSONValue, Metadata, ApiResponseData } from '../types/base-types.js';
import { isJSONValue, isMetadata } from '../utils/type-guards.js';

interface ApiResponse {
  data: JSONValue;
  metadata?: Metadata;
}

function processResponse(response: ApiResponse) {
  if (isJSONValue(response.data)) {
    // Type-safe access
    return response.data;
  }
  throw new Error('Invalid response data');
}

// For untyped API responses
function handleUnknownResponse(data: unknown): ApiResponseData {
  if (isDict(data, isJSONValue)) {
    return data;
  }
  throw new Error('Invalid API response format');
}
```

### 2. Configuration Objects

#### Before:
```typescript
interface ServiceConfig {
  settings: Record<string, any>;
  environment: any;
}

function loadConfig(): any {
  return JSON.parse(fs.readFileSync('config.json', 'utf8'));
}
```

#### After:
```typescript
import type { Config, EnvironmentConfig } from '../types/base-types.js';
import { isConfig, isEnvironmentConfig } from '../utils/type-guards.js';

interface ServiceConfig {
  settings: Config;
  environment?: EnvironmentConfig;
}

function loadConfig(): Config {
  const data = JSON.parse(fs.readFileSync('config.json', 'utf8'));

  if (!isConfig(data)) {
    throw new Error('Invalid configuration format');
  }

  return data;
}

// With runtime validation
function validateConfig(config: unknown): ServiceConfig {
  if (!isDict(config, isJSONValue)) {
    throw new Error('Config must be a dictionary');
  }

  const { settings, environment } = config;

  if (!isConfig(settings)) {
    throw new Error('Invalid settings configuration');
  }

  if (environment && !isEnvironmentConfig(environment)) {
    throw new Error('Invalid environment configuration');
  }

  return { settings, environment };
}
```

### 3. Metadata and Tagging Systems

#### Before:
```typescript
interface Entity {
  id: string;
  metadata: Record<string, any>;
  tags: any;
}

function updateMetadata(entity: any, key: string, value: any) {
  entity.metadata[key] = value;
}
```

#### After:
```typescript
import type { Metadata, Tags, ExtendedTags } from '../types/base-types.js';
import { isMetadata, isTagsStrict } from '../utils/type-guards.js';

interface Entity {
  id: string;
  metadata?: Metadata;
  tags?: Tags;
}

function updateMetadata(entity: Entity, key: string, value: JSONValue) {
  if (!entity.metadata) {
    entity.metadata = { tags: {} };
  }

  entity.metadata[key] = value;
}

// With validation
function addTag(entity: Entity, key: string, value: string): void {
  if (!entity.tags) {
    entity.tags = {};
  }

  // Validate tag format
  if (!isTagsStrict({ [key]: value })) {
    throw new Error(`Invalid tag: ${key} = ${value}`);
  }

  entity.tags[key] = value;
}

// Extended tags with structured data
function addExtendedTag(
  entity: Entity,
  category: string,
  tags: ExtendedTags
): void {
  if (!entity.metadata) {
    entity.metadata = { tags: {} };
  }

  if (!entity.metadata.tags) {
    entity.metadata.tags = {};
  }

  entity.metadata.tags[category] = JSON.stringify(tags);
}
```

### 4. Dictionary and Map Patterns

#### Before:
```typescript
function processDictionary(dict: Record<string, any>) {
  return Object.entries(dict).map(([key, value]) => {
    // No type safety for value
    return `${key}: ${value}`;
  });
}
```

#### After:
```typescript
import type { Dict, MutableDict } from '../types/base-types.js';
import { isDict, isString } from '../utils/type-guards.js';

function processStringDictionary(dict: Dict<string>): string[] {
  return Object.entries(dict).map(([key, value]) => `${key}: ${value}`);
}

// With validation for unknown data
function processUnknownDictionary(data: unknown): string[] {
  if (!isDict(data, isString)) {
    throw new Error('Expected dictionary with string values');
  }

  return processStringDictionary(data);
}

// Mutable dictionary when updates are needed
function updateDictionary(
  dict: MutableDict<number>,
  key: string,
  value: number
): void {
  dict[key] = value;
}
```

### 5. Event Handling and Messaging

#### Before:
```typescript
interface Event {
  type: string;
  data: any;
  timestamp: any;
}

function handleEvent(event: any) {
  console.log(event.data.someProperty);
}
```

#### After:
```typescript
import type { BaseEvent, EventHandler } from '../types/base-types.js';
import { isBaseEvent } from '../utils/type-guards.js';

interface CustomEvent extends BaseEvent {
  type: 'CUSTOM_EVENT';
  data: {
    userId: string;
    action: string;
  };
}

function handleEvent(event: CustomEvent): void {
  // Type-safe access
  console.log(`User ${event.data.userId} performed ${event.data.action}`);
}

// With validation for external events
function handleUnknownEvent(data: unknown): void {
  if (!isBaseEvent(data)) {
    throw new Error('Invalid event format');
  }

  switch (data.type) {
    case 'CUSTOM_EVENT':
      handleEvent(data as CustomEvent);
      break;
    default:
      console.log(`Unhandled event type: ${data.type}`);
  }
}

// Type-safe event handler
const customEventHandler: EventHandler<CustomEvent> = (event) => {
  console.log(`Processing custom event: ${event.id}`);
};
```

### 6. Query Parameters and Headers

#### Before:
```typescript
function buildQuery(params: any): string {
  return new URLSearchParams(params).toString();
}

function setHeaders(headers: any): Headers {
  return new Headers(headers);
}
```

#### After:
```typescript
import type { QueryParams, Headers as CustomHeaders } from '../types/base-types.js';
import { isQueryParams, isHeaders } from '../utils/type-guards.js';

function buildQuery(params: QueryParams): string {
  const searchParams = new URLSearchParams();

  Object.entries(params).forEach(([key, value]) => {
    searchParams.append(key, String(value));
  });

  return searchParams.toString();
}

function buildQueryFromUnknown(data: unknown): string {
  if (!isQueryParams(data)) {
    throw new Error('Invalid query parameters');
  }

  return buildQuery(data);
}

function setCustomHeaders(headers: CustomHeaders): Record<string, string> {
  // Type-safe header manipulation
  return { ...headers };
}

function setHeadersFromUnknown(data: unknown): Record<string, string> {
  if (!isHeaders(data)) {
    throw new Error('Invalid headers format');
  }

  return setCustomHeaders(data);
}
```

### 7. Result and Error Handling

#### Before:
```typescript
function riskyOperation(): any {
  try {
    return { success: true, data: someData };
  } catch (error) {
    return { success: false, error: error.message };
  }
}
```

#### After:
```typescript
import type { Result, AsyncResult } from '../types/base-types.js';
import { isResult } from '../utils/type-guards.js';

function riskyOperation(): Result<string, Error> {
  try {
    const data = someOperation();
    return { success: true, data };
  } catch (error) {
    return { success: false, error: error as Error };
  }
}

// Async version
async function asyncRiskyOperation(): AsyncResult<string> {
  try {
    const data = await someAsyncOperation();
    return { success: true, data };
  } catch (error) {
    return { success: false, error: error as Error };
  }
}

// With validation
function handleUnknownResult(data: unknown): string {
  if (!isResult(data, isString, (error): error is Error => error instanceof Error)) {
    throw new Error('Invalid result format');
  }

  if (data.success) {
    return data.data;
  } else {
    throw data.error;
  }
}
```

## Advanced Patterns

### 1. Generic Type Guards

```typescript
import { and, or, optional, transform } from '../utils/type-guards.js';

// Create specialized guards
const isStringOrNumber = or(isString, isNumber);
const isNonEmptyString = and(isString, (s): s is string => s.trim().length > 0);
const isOptionalString = optional(isString);

// Transform then validate
const isValidDateString = transform(
  (value) => new Date(value as string),
  (date): date is Date => !isNaN(date.getTime())
);
```

### 2. Strict Validation Options

```typescript
// Strict tag validation with constraints
const tags = { 'user-id': '123', 'role': 'admin', 'session-id': 'abc123' };

if (isTagsStrict(tags, {
  maxTags: 10,
  maxTagLength: 50,
  allowedTagKeys: new Set(['user-id', 'role', 'session-id']),
  tagKeyPattern: /^[a-z-]+$/,
  tagValuePattern: /^[a-zA-Z0-9-]+$/
})) {
  // Tags are valid
}
```

### 3. Configuration Validation

```typescript
// Deep configuration validation
const config = {
  database: {
    host: 'localhost',
    port: 5432,
    ssl: true
  },
  cache: {
    ttl: 3600,
    maxSize: 1000
  }
};

if (isConfig(config, { maxDepth: 5, allowFunctions: false })) {
  // Configuration is valid
}
```

## Migration Strategy

### Phase 1: Identify `any` Usage
1. Search for `: any` patterns in the codebase
2. Categorize by use case (JSON, metadata, config, etc.)
3. Prioritize high-impact areas (API boundaries, configuration)

### Phase 2: Gradual Migration
1. Start with new base types for new code
2. Replace simple `any` patterns first
3. Add runtime validation at boundaries
4. Update existing code incrementally

### Phase 3: Validation and Testing
1. Add comprehensive tests for type guards
2. Validate data at API boundaries
3. Add error handling for invalid data
4. Monitor for runtime issues

### Phase 4: Enforcement
1. Enable ESLint rules for `@typescript-eslint/no-explicit-any`
2. Add type coverage metrics
3. Regular audits of remaining `any` usage

## Best Practices

1. **Always validate at boundaries**: Use type guards when receiving external data
2. **Prefer strict variants**: Use `isJSONValueStrict` over `isJSONValue` when possible
3. **Document constraints**: Use validation options to enforce business rules
4. **Provide fallbacks**: Handle validation failures gracefully
5. **Test type guards**: Write comprehensive tests for validation logic

## Common Pitfalls

1. **Missing validation**: Don't forget to use type guards at runtime
2. **Overly strict validation**: Balance safety with flexibility
3. **Inconsistent migration**: Apply patterns consistently across the codebase
4. **Performance concerns**: Cache validation results for repeated checks

## Tooling

### ESLint Configuration

```json
{
  "rules": {
    "@typescript-eslint/no-explicit-any": "error",
    "@typescript-eslint/no-unsafe-assignment": "warn",
    "@typescript-eslint/no-unsafe-member-access": "warn",
    "@typescript-eslint/no-unsafe-call": "warn",
    "@typescript-eslint/no-unsafe-return": "warn"
  }
}
```

### Type Coverage

Use tools like `type-coverage` to monitor type safety:

```bash
npm install -g type-coverage
type-coverage --detail
```

## Conclusion

This migration provides a systematic approach to eliminating `any` usage while maintaining the flexibility needed for dynamic data. The combination of compile-time types and runtime validation ensures both type safety and robustness.