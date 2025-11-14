# Safe Base Types Overview

This document provides an overview of the new safe base types system introduced to replace common `any` usage patterns in the Cortex MCP system.

## Purpose

The safe base types system aims to:
- Eliminate `any` usage while maintaining flexibility
- Provide compile-time type safety
- Enable runtime validation at system boundaries
- Support common patterns like JSON handling, configuration, and metadata

## Core Files

### `src/types/base-types.ts`
Contains all the base type definitions and basic type guards.

### `src/utils/type-guards.ts`
Contains comprehensive runtime type guards for validation.

### `docs/any-to-safe-types-migration.md`
Detailed migration guide with examples and best practices.

## Key Type Categories

### 1. JSON-Safe Types
```typescript
type JSONPrimitive = string | number | boolean | null;
type JSONValue = JSONPrimitive | JSONObject | JSONArray;
interface JSONObject { [key: string]: JSONValue; }
interface JSONArray extends Array<JSONValue> {}
```

### 2. Dictionary Types
```typescript
type Dict<T> = { readonly [key: string]: T; };
type MutableDict<T> = { [key: string]: T; };
type PartialDict<T> = { readonly [key: string]: T | undefined; };
```

### 3. Metadata and Tagging
```typescript
interface Metadata {
  readonly tags?: Tags;
  readonly version?: string;
  readonly source?: string;
  readonly timestamp?: string;
  readonly [key: string]: JSONValue;
}

type Tags = Dict<string>;
type ExtendedTags = Dict<string | JSONValue>;
type CategorizedTags = { readonly [category: string]: Tags; };
```

### 4. Configuration Types
```typescript
type Config = Dict<JSONValue>;
interface EnvironmentConfig {
  readonly development?: Config;
  readonly staging?: Config;
  readonly production?: Config;
  readonly test?: Config;
}
```

### 5. Event and Message Types
```typescript
interface BaseEvent {
  readonly type: string;
  readonly timestamp: string;
  readonly id: string;
  readonly data?: Dict<JSONValue>;
  readonly metadata?: Metadata;
}

interface MessagePayload {
  readonly id: string;
  readonly type: string;
  readonly data: JSONValue;
  readonly timestamp: string;
  readonly correlationId?: string;
}
```

### 6. Result Types
```typescript
type Result<T, E = Error> =
  | { readonly success: true; readonly data: T }
  | { readonly success: false; readonly error: E };

type AsyncResult<T, E = Error> = Promise<Result<T, E>>;
```

## Type Guard Categories

### Basic Validation
- `isJSONValue()` - Validate any JSON value
- `isDict()` - Validate dictionaries with specific value types
- `isTags()` - Validate tag structures
- `isMetadata()` - Validate metadata objects

### Strict Validation
- `isJSONValueStrict()` - JSON validation with depth protection
- `isJSONObjectStrict()` - Object validation with prototype checking
- `isTagsStrict()` - Tag validation with constraints
- `isMetadataStrict()` - Metadata validation with size limits

### Specialized Validation
- `isQueryParams()` - Validate URL query parameters
- `isHeaders()` - Validate HTTP headers
- `isBaseEvent()` - Validate event structures
- `isConfig()` - Validate configuration objects

### Utility Guards
- `isString()`, `isNumber()`, `isBoolean()` - Primitive validation
- `isValidUUID()`, `isValidEmail()`, `isValidURL()` - Format validation
- `isArray()` - Array validation with item type checking

## Usage Patterns

### 1. API Boundary Validation
```typescript
import { isJSONValue, isMetadata } from '../utils/type-guards.js';

function handleApiResponse(data: unknown): ApiResponse {
  if (!isJSONValue(data)) {
    throw new Error('Invalid API response');
  }

  return data as ApiResponse;
}
```

### 2. Configuration Loading
```typescript
import { isConfig } from '../utils/type-guards.js';

function loadConfig(path: string): Config {
  const data = JSON.parse(fs.readFileSync(path, 'utf8'));

  if (!isConfig(data)) {
    throw new Error('Invalid configuration format');
  }

  return data;
}
```

### 3. Tag Management
```typescript
import { isTagsStrict } from '../utils/type-guards.js';

function addTag(tags: Tags, key: string, value: string): Tags {
  if (!isTagsStrict({ [key]: value }, {
    maxTagLength: 100,
    tagKeyPattern: /^[a-z0-9-]+$/
  })) {
    throw new Error('Invalid tag format');
  }

  return { ...tags, [key]: value };
}
```

## Advanced Features

### Guard Composition
```typescript
import { and, or, optional, transform } from '../utils/type-guards.js';

// Combine guards with AND logic
const isPositiveInteger = and(
  (value: unknown): value is number => typeof value === 'number',
  (value: number): value is number => value > 0 && Number.isInteger(value)
);

// Optional validation
const isOptionalString = optional(isString);

// Transform then validate
const isValidDate = transform(
  (value: unknown) => new Date(value as string),
  (date): date is Date => !isNaN(date.getTime())
);
```

### Validation Options
```typescript
// Strict tag validation
const isValidTags = isTagsStrict(tags, {
  maxTags: 100,
  maxTagLength: 200,
  allowedTagKeys: new Set(['env', 'service', 'version']),
  tagKeyPattern: /^[a-z-]+$/,
  tagValuePattern: /^[a-zA-Z0-9._\s-]+$/
});

// Configuration validation
const isValidConfig = isConfig(config, {
  maxDepth: 5,
  allowFunctions: false
});
```

## Migration Benefits

1. **Type Safety**: Compile-time checking catches errors early
2. **Runtime Validation**: Boundary validation prevents invalid data
3. **Self-Documenting**: Types communicate intent and structure
4. **Refactoring Safety**: Changes are caught by the type system
5. **IDE Support**: Better autocomplete and navigation

## Performance Considerations

- Type guards add minimal runtime overhead
- Validation is only performed when needed
- Caching can be implemented for repeated validations
- Strict variants provide additional safety checks

## Best Practices

1. **Validate at Boundaries**: Check data when entering the system
2. **Use Strict Variants**: Prefer strict validation for security-sensitive data
3. **Handle Validation Failures**: Provide clear error messages
4. **Document Constraints**: Use validation options to enforce business rules
5. **Test Type Guards**: Write comprehensive tests for validation logic

## Common Anti-Patterns to Avoid

1. **Bypassing Validation**: Don't use type assertions without validation
2. **Overly Permissive Types**: Avoid `any` even with type guards
3. **Inconsistent Validation**: Apply validation consistently
4. **Silent Failures**: Always handle validation errors explicitly

## Integration with Existing Code

The safe types system is designed to integrate seamlessly with existing code:

- Existing interfaces can extend base types
- Gradual migration is possible
- Backward compatibility is maintained
- Performance impact is minimal

## Future Enhancements

- Schema-based validation generation
- Automatic type guard generation
- Performance optimizations
- Additional specialized types
- Enhanced error reporting

## Conclusion

The safe base types system provides a comprehensive solution for eliminating `any` usage while maintaining the flexibility needed for dynamic data processing. By combining compile-time types with runtime validation, it offers both developer productivity and runtime safety.