# Comprehensive Type Guards System Guide

## Overview

This document describes the comprehensive type guards system designed to replace `any` usage throughout the codebase with runtime type safety. The system provides reusable, high-performance type guards that can validate data structures at runtime while maintaining TypeScript type safety.

## Features

- **Runtime Type Safety**: Validate unknown data at runtime
- **Composable Guards**: Combine multiple guards with logic operators
- **Performance Optimized**: Memoization and early-return optimizations
- **Schema-Based Validation**: Support for complex nested structures
- **Error Handling**: Comprehensive error type guards
- **Configuration Validation**: Built-in guards for common configuration patterns

## Quick Start

### Basic Usage

```typescript
import { isString, isNumber, isValidUUID, isKnowledgeItem } from '../src/utils/type-guards.js';

function processUnknownData(data: unknown) {
  if (isString(data)) {
    // TypeScript knows data is string here
    console.log(`Processing string: ${data.toUpperCase()}`);
    return;
  }

  if (isValidUUID(data)) {
    // TypeScript knows data is a valid UUID string
    console.log(`Processing UUID: ${data}`);
    return;
  }

  if (isKnowledgeItem(data)) {
    // TypeScript knows data is a KnowledgeItem
    console.log(`Processing knowledge item: ${data.kind}`);
    return;
  }

  console.log('Unknown data type');
}
```

### Guard Composition

```typescript
import { and, or, hasProperty, exactShape, arrayOf } from '../src/utils/type-guards.js';

// Create specialized guards
const isUser = exactShape({
  id: isString,
  name: isString,
  email: (value): value is string => typeof value === 'string' && value.includes('@'),
  age: (value): value is number => typeof value === 'number' && value >= 0,
  isActive: optional(isBoolean)
});

const isPositiveNumber = and(isNumber, (n): n is number => n > 0);
const isStringOrNumber = or(isString, isNumber);
const hasUserId = hasProperty('id', isString);
const isUserArray = arrayOf(isUser, { minLength: 1, maxLength: 100 });
```

## Available Type Guards

### Basic Type Guards

| Guard | Description | Example |
|-------|-------------|---------|
| `isString(value)` | Checks if value is a string | `isString("hello") // true` |
| `isNumber(value)` | Checks if value is a finite number | `isNumber(42) // true` |
| `isBoolean(value)` | Checks if value is a boolean | `isBoolean(true) // true` |
| `isNonEmptyString(value)` | Checks if value is a non-empty string | `isNonEmptyString("hello") // true` |
| `isValidUUID(value)` | Validates UUID format | `isValidUUID("123e4567-e89b-12d3-a456-426614174000") // true` |
| `isValidISODate(value)` | Validates ISO date format | `isValidISODate("2024-01-01T00:00:00.000Z") // true` |
| `isValidURL(value)` | Validates URL format | `isValidURL("https://example.com") // true` |
| `isValidEmail(value)` | Validates email format | `isValidEmail("test@example.com") // true` |

### API Response Guards

| Guard | Description | Example |
|-------|-------------|---------|
| `isSuccessResponse(value, dataGuard?)` | Validates success responses | `isSuccessResponse({ success: true, data: "result" }) // true` |
| `isErrorResponse(value, errorCodeGuard?)` | Validates error responses | `isErrorResponse({ success: false, error: { code: "ERR", message: "Error" } }) // true` |
| `isStandardApiResponse(value, dataGuard?)` | Validates any API response | `isStandardApiResponse(response) // true` |
| `isMCPToolResponse(value)` | Validates MCP tool responses | `isMCPToolResponse({ content: [], isError: false }) // true` |

### Knowledge Item Guards

| Guard | Description | Example |
|-------|-------------|---------|
| `isKnowledgeItem(value)` | Validates KnowledgeItem structure | `isKnowledgeItem(item) // true` |
| `isSearchQuery(value)` | Validates SearchQuery structure | `isSearchQuery(query) // true` |
| `isSearchResult(value)` | Validates SearchResult structure | `isSearchResult(result) // true` |
| `isKnowledgeScope(value)` | Validates scope object | `isKnowledgeScope({ project: "my-project" }) // true` |

### Configuration Guards

| Guard | Description | Example |
|-------|-------------|---------|
| `isDatabaseConfig(value)` | Validates database configuration | `isDatabaseConfig(config) // true` |
| `isQdrantConfig(value)` | Validates Qdrant configuration | `isQdrantConfig(config) // true` |
| `isAuthConfig(value)` | Validates authentication configuration | `isAuthConfig(config) // true` |
| `isServiceConfig(value)` | Validates service configuration | `isServiceConfig(config) // true` |

### Error Type Guards

| Guard | Description | Example |
|-------|-------------|---------|
| `isValidationError(value)` | Validates validation errors | `isValidationError({ code: "ERR", message: "Error" }) // true` |
| `isSystemError(value)` | Validates system errors | `isSystemError({ code: "ERR", message: "Error", category: "database", severity: "high", retryable: true }) // true` |
| `isDatabaseError(value)` | Validates database errors | `isDatabaseError({ code: "QUERY_FAILED", database: "mydb", retryable: true }) // true` |
| `isNetworkError(value)` | Validates network errors | `isNetworkError({ code: "HTTP_404", statusCode: 404, retryable: false }) // true` |

## Guard Composition Utilities

### Logic Operators

```typescript
// AND - All guards must pass
const isPositiveInteger = and(isNumber, (n): n is number => n > 0 && Number.isInteger(n));

// OR - At least one guard must pass
const isStringOrNumber = or(isString, isNumber);

// Optional - Allows null/undefined
const optionalString = optional(isString);
```

### Array Validation

```typescript
// Basic array validation
const stringArray = arrayOf(isString);

// With constraints
const userArray = arrayOf(isUser, {
  minLength: 1,
  maxLength: 100,
  uniqueItems: true,
  allowNullItems: false
});
```

### Object Property Validation

```typescript
// Single property
const hasId = hasProperty('id', isString);

// Multiple properties
const hasIdAndName = hasProperties({
  id: isString,
  name: isString,
  age: (value): value is number => typeof value === 'number' && value >= 0
});

// Exact shape (all properties must be present)
const userShape = exactShape({
  id: isString,
  name: isString,
  email: isString
});

// Partial shape (some properties optional)
const userPartial = partialShape({
  id: isString,
  name: isString,
  bio: optional(isString)
});
```

### Value Constraints

```typescript
// Enum-like validation
const isStatus = oneOfValues(['active', 'inactive', 'pending'] as const);

// Range validation
const isAge = numberRange(0, 120, { integer: true });
const isPercentage = numberRange(0, 100, { inclusive: false });

// Pattern validation
const isEmail = stringPattern(/^[^\s@]+@[^\s@]+\.[^\s@]+$/);
const isSlug = stringPattern(/^[a-z0-9-]+$/);

// Length validation
const isPassword = stringLength(8, 128);
const isUsername = stringLength(3, 30);
```

## Schema-Based Guards

### Nested Object Validation

```typescript
import { nestedObject, oneOfValues, stringLength, isValidURL } from '../src/utils/type-guards.js';

const userSchema = nestedObject({
  id: { validate: isString, required: true },
  profile: {
    validate: nestedObject({
      name: { validate: stringLength(1, 100), required: true },
      bio: { validate: optional(stringLength(0, 500)), required: false },
      avatar: { validate: optional(isValidURL), required: false },
    }),
    required: true,
  },
  preferences: {
    validate: nestedObject({
      theme: { validate: oneOfValues(['light', 'dark', 'auto']), required: true },
      notifications: { validate: isBoolean, required: true },
    }),
    required: false,
  }
}, { strict: true }); // Reject extra properties

if (userSchema(unknownData)) {
  // TypeScript knows unknownData matches the schema
  console.log(`User: ${unknownData.profile.name}`);
}
```

### Collection Validation

```typescript
import { collectionSchema, exactShape } from '../src/utils/type-guards.js';

const userCollection = collectionSchema(
  { validate: exactShape({ id: isString, name: isString }) },
  {
    minLength: 1,
    maxLength: 100,
    uniqueKey: 'id', // Ensure unique IDs
    sortBy: 'name'   // Optional sorting validation
  }
);

if (userCollection(unknownArray)) {
  console.log(`Valid collection with ${unknownArray.length} users`);
}
```

### Discriminated Unions

```typescript
// Define content types
type TextContent = { type: 'text'; content: string };
type ImageContent = { type: 'image'; url: string; alt?: string };
type VideoContent = { type: 'video'; url: string; duration: number };

// Create discriminated guards
const isTextContent = discriminatedUnion('type', 'text',
  hasProperties({ content: isString })
);

const isImageContent = discriminatedUnion('type', 'image',
  hasProperties({ url: isValidURL })
);

// Union guard
const isContent = oneOf('type', {
  text: isTextContent,
  image: isImageContent,
  video: isVideoContent,
});

function processContent(content: unknown) {
  if (isContent(content)) {
    switch (content.type) {
      case 'text':
        console.log(`Text: ${content.content}`);
        break;
      case 'image':
        console.log(`Image: ${content.url}`);
        break;
      case 'video':
        console.log(`Video: ${content.url} (${content.duration}s)`);
        break;
    }
  }
}
```

## Performance Optimization

### Memoization

```typescript
import { memoized } from '../src/utils/type-guards.js';

// Create an expensive guard
const expensiveUserGuard = (value: unknown): value is User => {
  // Simulate expensive validation
  return isUser(value);
};

// Create memoized version
const memoizedUserGuard = memoized(expensiveUserGuard, (user) => (user as User).id);

// First call performs validation
const result1 = memoizedUserGuard(userData);

// Subsequent calls with same ID use cache
const result2 = memoizedUserGuard(userData);
```

### Fast-Fail Guards

```typescript
import { fastFail } from '../src/utils/type-guards.js';

// Create a guard that quickly rejects common invalid types
const isUserFast = fastFail(isUser, ['string', 'number', 'boolean']);

// Quickly fails on primitive types
const result = isUserFast(someUnknownData);
```

### Performance Monitoring

```typescript
import { GuardPerformance } from '../src/utils/type-guards.js';

// Wrap guard with performance monitoring
const monitoredGuard = GuardPerformance.wrap('user-validation', isUser);

// Use the monitored guard
monitoredGuard(userData);
monitoredGuard(invalidData);

// Get performance metrics
const metrics = GuardPerformance.getMetrics('user-validation');
console.log(`Average time: ${metrics?.averageTime}ms`);
console.log(`Error rate: ${metrics?.errors / metrics?.calls * 100}%`);
```

## Best Practices

### 1. Guard Reusability

Create reusable guards for common patterns:

```typescript
// Common patterns
export const isPositiveInteger = and(isNumber, (n): n is number => n > 0 && Number.isInteger(n));
export const isNonEmptyArray = <T>(itemGuard: (value: unknown) => value is T) =>
  arrayOf(itemGuard, { minLength: 1 });
export const isRequiredString = (value: unknown): value is string =>
  isString(value) && value.trim().length > 0;
```

### 2. Early Validation

Validate data as early as possible, especially at API boundaries:

```typescript
// API endpoint
app.post('/users', (req, res) => {
  if (!isUser(req.body)) {
    return res.status(400).json({ error: 'Invalid user data' });
  }

  // TypeScript knows req.body is User here
  createUser(req.body);
});
```

### 3. Error Handling

Use type guards in error handling:

```typescript
function handleApiError(error: unknown) {
  if (isValidationError(error)) {
    console.log(`Validation failed: ${error.message} at ${error.path}`);
  } else if (isNetworkError(error)) {
    console.log(`Network error: ${error.code} - ${error.message}`);
  } else if (isSystemError(error)) {
    console.log(`System error: ${error.category}/${error.severity}`);
    if (error.retryable) {
      scheduleRetry();
    }
  } else {
    console.log('Unknown error:', error);
  }
}
```

### 4. Configuration Validation

Validate configuration at startup:

```typescript
function validateAppConfig(config: unknown): asserts config is AppConfig {
  if (!isDatabaseConfig(config.database)) {
    throw new Error('Invalid database configuration');
  }

  if (!isAuthConfig(config.auth)) {
    throw new Error('Invalid authentication configuration');
  }

  // Additional validations...
}
```

### 5. Testing Guards

Test guards thoroughly with various inputs:

```typescript
describe('isUser', () => {
  it('should validate valid user', () => {
    const validUser = { id: '1', name: 'John', email: 'john@example.com', age: 30 };
    expect(isUser(validUser)).toBe(true);
  });

  it('should reject invalid user', () => {
    expect(isUser({})).toBe(false);
    expect(isUser({ id: 1, name: 'John' })).toBe(false); // id should be string
    expect(isUser({ id: '1', name: 'John', age: -5 })).toBe(false); // invalid age
  });
});
```

## Migration Guide

### Replacing `any` Types

1. **Identify `any` usage**: Search for `any` in the codebase
2. **Create appropriate guards**: Define type guards for the expected data structure
3. **Add validation**: Insert guard checks where data enters the system
4. **Update types**: Replace `any` with specific types where possible

**Before:**
```typescript
function processData(data: any) {
  console.log(data.name);
  return data.age * 2;
}
```

**After:**
```typescript
function processData(data: unknown) {
  if (!isUser(data)) {
    throw new Error('Invalid user data');
  }

  console.log(data.name); // TypeScript knows data.name exists
  return data.age * 2;    // TypeScript knows data.age is number
}
```

### Progressive Adoption

Start with high-risk areas:
1. API input validation
2. Configuration loading
3. External service responses
4. Database results

Gradually expand to cover more areas of the codebase.

## Conclusion

The comprehensive type guards system provides a robust foundation for runtime type safety in the application. By replacing `any` usage with proper type guards, we can:

- Catch type errors at runtime instead of in production
- Improve code reliability and maintainability
- Enable better IDE support and autocomplete
- Provide clear validation error messages
- Ensure data consistency across the application

The system is designed to be performant, composable, and easy to use, making it practical for adoption in large codebases.