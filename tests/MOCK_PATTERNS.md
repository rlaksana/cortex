# Mock Patterns and Testing Guidelines

This document provides comprehensive guidelines for using the standardized mock templates in the MCP Cortex test suite.

## Table of Contents

1. [Overview](#overview)
2. [Getting Started](#getting-started)
3. [Mock Templates](#mock-templates)
4. [Common Testing Patterns](#common-testing-patterns)
5. [Best Practices](#best-practices)
6. [Examples](#examples)
7. [Troubleshooting](#troubleshooting)

## Overview

The mock system is designed to eliminate repetitive mock setup and ensure consistency across all test files. It provides standardized mocks for the most commonly used dependencies in the MCP Cortex application.

### Key Benefits

- **Consistency**: Standardized mock behavior across all tests
- **Productivity**: Reduce boilerplate code in test files
- **Maintainability**: Centralized mock management
- **Flexibility**: Configurable mock behavior for different scenarios
- **Type Safety**: Full TypeScript support with proper typing

## Getting Started

### Basic Setup

Import the mock utilities at the top of your test file:

```typescript
// Import mock templates
import { testUtils } from '../setup-mocks';

// Or import specific utilities
import { createMockEnvironment, MockDataGenerators } from '../utils/mock-templates';
```

### Quick Start Example

```typescript
import { describe, it, expect, vi } from 'vitest';
import { testUtils } from '../setup-mocks';

describe('My Service', () => {
  const mockEnv = testUtils.createTestEnvironment();
  const mockQdrant = testUtils.mocks.createSuccessfulQdrantClient();

  it('should perform basic operation', async () => {
    // Arrange - mocks are already set up
    // Act - test your service
    // Assert - verify behavior
    expect(mockQdrant.search).toHaveBeenCalled();
  });
});
```

## Mock Templates

### Environment Mock

The environment mock provides controlled access to configuration values.

```typescript
const mockEnv = testUtils.createMockEnvironment({
  NODE_ENV: 'test',
  ENABLE_AUTH: false,
  QDRANT_URL: 'http://test:6333',
  OPENAI_API_KEY: 'test-key',
});

// Usage
const config = mockEnv.getInstance();
config.getQdrantConfig(); // Returns mocked config
config.isTestMode(); // Returns true
```

#### Available Configuration Options

```typescript
interface MockEnvironmentConfig {
  NODE_ENV?: 'development' | 'production' | 'test';
  LOG_LEVEL?: 'error' | 'warn' | 'info' | 'debug' | 'trace';
  ENABLE_AUTH?: boolean;
  ENABLE_CACHING?: boolean;
  ENABLE_METRICS?: boolean;
  QDRANT_URL?: string;
  OPENAI_API_KEY?: string;
  VECTOR_SIZE?: 384 | 768 | 1024 | 1536 | 2048 | 3072;
  SEARCH_LIMIT?: number;
  SEARCH_THRESHOLD?: number;
  JWT_SECRET?: string;
  ENCRYPTION_KEY?: string;
  MOCK_EXTERNAL_SERVICES?: boolean;
}
```

### Logger Mock

Provides a complete Pino logger mock with all standard methods.

```typescript
const mockLogger = testUtils.mocks.createMockLogger();

// Usage
mockLogger.info({ operation: 'test' }, 'Test message');
mockLogger.error({ error: new Error('test') }, 'Error message');

// Assertions
expect(mockLogger.info).toHaveBeenCalledWith(
  { operation: 'test' },
  'Test message'
);
```

### Qdrant Client Mock

Comprehensive mock for Qdrant operations including all extended knowledge entity methods.

```typescript
// Successful client
const mockQdrant = testUtils.mocks.createSuccessfulQdrantClient();

// Failing client
const failingQdrant = testUtils.mocks.createFailingQdrantClient(['search', 'upsert']);

// Custom configuration
const customQdrant = testUtils.createMockTestEnvironment({
  qdrant: {
    shouldFail: false,
    failMethods: ['delete'],
    collections: [{ name: 'test-collection', points_count: 100 }],
    searchResults: [MockDataGenerators.searchResult()],
    healthStatus: true,
  }
}).qdrantClient;
```

#### Extended Methods

The Qdrant mock includes all knowledge entity methods used in the codebase:

- `eventAudit`, `user`, `apiKey`, `tokenRevocationList`, `securityEvent`
- `adrDecision`, `section`, `runbook`, `changeLog`, `issueLog`, `todoLog`
- `releaseNote`, `ddlHistory`, `prContext`, `incidentLog`, `releaseLog`
- `riskLog`, `assumptionLog`, `knowledgeEntity`, `knowledgeRelation`, `knowledgeObservation`

### Database Adapter Mock

Mocks the database layer with configurable latency and failure modes.

```typescript
const mockDb = testUtils.mocks.createMockDatabaseAdapter({
  connectionStatus: 'connected',
  latency: 10, // Simulate 10ms latency
  shouldFail: false,
  failOperations: ['connect'],
});

// Usage
const health = await mockDb.healthCheck();
expect(health).toBe(true);

const results = await mockDb.find({ query: 'test' });
expect(results.results).toEqual([]);
```

### Auth Service Mock

Complete authentication service mock with JWT and user management.

```typescript
const mockAuth = testUtils.mocks.createMockAuthService({
  shouldFail: false,
  failOperations: ['validateUserWithDatabase'],
  validUsers: [MockDataGenerators.user({ role: 'admin' })],
  validApiKeys: [MockDataGenerators.apiKey()],
});

// Usage
const user = await mockAuth.validateUserWithDatabase('user', 'pass');
const token = mockAuth.generateAccessToken(user, 'session-id', ['read']);
```

### Memory Store Mock

Mocks memory operations for knowledge items.

```typescript
const mockStore = testUtils.mocks.createMockMemoryStore({
  shouldFail: false,
  storedItems: [MockDataGenerators.knowledgeItem()],
  searchResults: [MockDataGenerators.searchResult()],
});

// Usage
const result = await mockStore.store({
  kind: 'entity',
  content: 'test',
  scope: { project: 'test' }
});
```

## Common Testing Patterns

### Scenario-Based Testing

Use predefined scenarios for common test situations:

```typescript
// Successful operations
const successEnv = testUtils.scenarios.successfulMemoryStore();

// Database failures
const failingDbEnv = testUtils.scenarios.failingQdrant(['search']);

// Authentication failures
const authFailureEnv = testUtils.scenarios.authFailure();

// High latency simulation
const latencyEnv = testUtils.scenarios.highLatency(100);
```

### Time-Dependent Testing

Use fake timers for time-sensitive operations:

```typescript
it('should handle timeouts', async () => {
  const fakeTimers = testUtils.useFakeTimers();

  // Start async operation
  const promise = service.timeoutOperation();

  // Advance time
  fakeTimers.advanceTimeBy(5000);

  // Verify timeout behavior
  await expect(promise).rejects.toThrow('Timeout');

  // Clean up
  fakeTimers.runOnlyPendingTimers();
});
```

### Assertion Helpers

Use specialized assertion helpers for common patterns:

```typescript
// Verify user validation
testUtils.expect.toHaveBeenCalledWithValidUser(mockAuth.validateUserWithDatabase);

// Verify search queries
testUtils.expect.toHaveBeenCalledWithValidQuery(mockQdrant.search);

// Verify knowledge items
testUtils.expect.toHaveBeenCalledWithKnowledgeItem(mockStore.store);
```

### Environment Reset

Each test runs with a clean environment:

```typescript
beforeEach(() => {
  // All mocks are automatically cleared
  // Environment is reset to test defaults
});

afterEach(() => {
  // Timers are cleared
  // Fake timers are reset
});
```

## Best Practices

### 1. Use Specific Mocks

Prefer specific mocks over generic ones:

```typescript
// Good
const mockAuth = testUtils.mocks.createMockAuthService({
  validUsers: [MockDataGenerators.user({ role: 'admin' })]
});

// Avoid
const mockAuth = { validateUserWithDatabase: vi.fn() };
```

### 2. Configure Failures Explicitly

When testing error scenarios, be explicit about what should fail:

```typescript
// Good
const failingQdrant = testUtils.mocks.createFailingQdrantClient(['search']);

// Avoid
const mockQdrant = vi.fn(() => { throw new Error(); });
```

### 3. Use Realistic Data

Use the provided data generators for realistic test data:

```typescript
// Good
const user = MockDataGenerators.user({ role: 'admin' });
const item = MockDataGenerators.knowledgeItem({ kind: 'decision' });

// Avoid
const user = { id: '1', name: 'test' };
```

### 4. Test Both Success and Failure Paths

Always test both success and failure scenarios:

```typescript
describe('Service', () => {
  describe('when database is healthy', () => {
    const env = testUtils.scenarios.successfulMemoryStore();
    // Test success scenarios
  });

  describe('when database fails', () => {
    const env = testUtils.scenarios.failingQdrant(['search']);
    // Test error handling
  });
});
```

### 5. Verify Mock Interactions

Always verify that your mocks were called correctly:

```typescript
it('should search with correct parameters', async () => {
  const mockQdrant = testUtils.mocks.createSuccessfulQdrantClient();

  await service.findItems({ query: 'test', limit: 10 });

  expect(mockQdrant.search).toHaveBeenCalledWith({
    vector: expect.any(Array),
    limit: 10,
    filter: expect.any(Object)
  });
});
```

## Examples

### Example 1: Basic Service Test

```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { testUtils } from '../setup-mocks';
import { MyService } from '../src/my-service';

describe('MyService', () => {
  let service: MyService;
  let mockEnv: any;
  let mockQdrant: any;

  beforeEach(() => {
    const testEnv = testUtils.scenarios.successfulMemoryStore();
    mockEnv = testEnv.environment;
    mockQdrant = testEnv.qdrantClient;

    service = new MyService(mockEnv.getInstance(), mockQdrant);
  });

  it('should store items successfully', async () => {
    const item = MockDataGenerators.knowledgeItem();

    const result = await service.store(item);

    expect(result.id).toBeDefined();
    expect(mockQdrant.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        collection_name: 'test-cortex-memory',
        points: expect.any(Array)
      })
    );
  });

  it('should handle database failures gracefully', async () => {
    const failingEnv = testUtils.scenarios.failingQdrant(['upsert']);
    const failingService = new MyService(
      failingEnv.environment.getInstance(),
      failingEnv.qdrantClient
    );

    const item = MockDataGenerators.knowledgeItem();

    await expect(failingService.store(item)).rejects.toThrow('Database error');
  });
});
```

### Example 2: Authentication Test

```typescript
import { describe, it, expect } from 'vitest';
import { testUtils, MockDataGenerators } from '../setup-mocks';
import { AuthService } from '../src/auth/auth-service';

describe('AuthService', () => {
  it('should authenticate valid users', async () => {
    const mockAuth = testUtils.mocks.createMockAuthService({
      validUsers: [MockDataGenerators.user({
        username: 'testuser',
        role: 'admin'
      })]
    });

    const result = await mockAuth.validateUserWithDatabase('testuser', 'password');

    expect(result).toEqual(
      expect.objectContaining({
        username: 'testuser',
        role: 'admin'
      })
    );
  });

  it('should reject invalid credentials', async () => {
    const mockAuth = testUtils.mocks.createMockAuthService({
      failOperations: ['validateUserWithDatabase']
    });

    await expect(
      mockAuth.validateUserWithDatabase('invalid', 'credentials')
    ).rejects.toThrow();
  });
});
```

### Example 3: Performance Test

```typescript
import { describe, it, expect } from 'vitest';
import { testUtils } from '../setup-mocks';
import { SearchService } from '../src/search/search-service';

describe('SearchService Performance', () => {
  it('should complete search within timeout', async () => {
    const fakeTimers = testUtils.useFakeTimers();

    const mockEnv = testUtils.scenarios.highLatency(50); // 50ms latency
    const service = new SearchService(mockEnv.qdrantClient);

    const searchPromise = service.search({ query: 'test' });

    // Fast-forward time
    fakeTimers.advanceTimeBy(100);

    const result = await searchPromise;
    expect(result.results).toBeDefined();

    fakeTimers.runOnlyPendingTimers();
  });
});
```

## Troubleshooting

### Common Issues

#### 1. Mock Not Working

**Problem**: Mocked methods are not being called.

**Solution**: Ensure you're using the mock instance from the test environment:

```typescript
// Correct
const testEnv = testUtils.scenarios.successfulMemoryStore();
const service = new MyService(testEnv.environment.getInstance(), testEnv.qdrantClient);

// Incorrect
const mockQdrant = createMockQdrantClient(); // Don't call directly
```

#### 2. Type Errors

**Problem**: TypeScript errors about mock method signatures.

**Solution**: Use the proper mock factory functions:

```typescript
// Correct
const mockQdrant = testUtils.mocks.createSuccessfulQdrantClient();

// Incorrect
const mockQdrant = {
  search: vi.fn(), // Missing proper typing
};
```

#### 3. Async Test Timeouts

**Problem**: Tests timing out due to async operations.

**Solution**: Use fake timers or proper await:

```typescript
// Use fake timers
const fakeTimers = testUtils.useFakeTimers();
fakeTimers.advanceTimeBy(1000);

// Or properly await
await expect(service.operation()).resolves.toBeDefined();
```

#### 4. Mock State Leaking

**Problem**: Mock state leaking between tests.

**Solution**: The setup automatically clears mocks, but you can manually reset:

```typescript
afterEach(() => {
  testUtils.resetAllMocks(); // If needed
});
```

### Debugging Tips

1. **Enable Debug Logging**: Set `LOG_LEVEL: 'debug'` in mock environment
2. **Check Mock Calls**: Use `expect(mock.method).mock.calls` to inspect calls
3. **Use Test Scenarios**: Start with predefined scenarios before customizing
4. **Verify Mock Setup**: Ensure mocks are properly injected into services

### Getting Help

- Check the mock template source code in `tests/utils/mock-templates.ts`
- Review existing test files for patterns
- Use the assertion helpers for common verification patterns
- Consult the Vitest documentation for advanced mocking techniques

---

## Summary

This mock system provides a comprehensive foundation for testing the MCP Cortex application. By following these patterns and guidelines, you can:

- Write consistent, maintainable tests
- Reduce boilerplate and improve productivity
- Test complex scenarios with ease
- Ensure proper test isolation and cleanup

For questions or contributions to the mock system, please refer to the codebase or create issues in the project repository.