# Testing Guide

## Overview

This guide provides comprehensive instructions for testing the Cortex Memory MCP system, including unit tests, integration tests, performance tests, and end-to-end testing.

## Table of Contents

1. [Test Framework Architecture](#test-framework-architecture)
2. [Running Tests](#running-tests)
3. [Test Categories](#test-categories)
4. [Writing Tests](#writing-tests)
5. [Test Data Management](#test-data-management)
6. [Performance Testing](#performance-testing)
7. [Database Testing](#database-testing)
8. [Error Testing](#error-testing)
9. [CI/CD Integration](#cicd-integration)
10. [Troubleshooting](#troubleshooting)

## Test Framework Architecture

The testing framework is built around these core components:

### Core Framework
- **TestRunner**: Orchestrates test execution and reporting
- **TestContext**: Provides isolated test environments
- **TestAssertions**: Custom assertion helpers
- **MockDataGenerator**: Generates test data

### Helper Classes
- **TestDataFactory**: Creates test data for all 16 knowledge types
- **DatabaseTestHelper**: Manages test databases and schema
- **PerformanceTestHelper**: Measures performance metrics
- **ValidationTestHelper**: Tests validation rules
- **ErrorTestHelper**: Tests error handling

### Test Scenarios
- **Knowledge Management Tests**: CRUD operations
- **Search Functionality Tests**: Advanced search features
- **Similarity Tests**: Deduplication logic
- **Business Rules Tests**: Immutability constraints
- **Performance Tests**: Scalability and speed

## Running Tests

### Quick Start

```bash
# Run all tests
npm test

# Run specific test file
npm test -- tests/run-tests.ts

# Run tests with coverage
npm run test:coverage
```

### Manual Test Execution

```typescript
import { TestRunner } from './tests/framework/test-setup.js';
import { basicKnowledgeManagement } from './tests/scenarios/knowledge-management-tests.js';

const runner = new TestRunner();
await runner.initialize();

try {
  await runner.runScenario(basicKnowledgeManagement);
  runner.printSummary();
} finally {
  await runner.cleanup();
}
```

### Environment Setup

```bash
# Set test environment variables
export NODE_ENV=test
export DATABASE_URL="postgresql://test:test@localhost:5432/cortex_memory_test"
export LOG_LEVEL=error  # Reduce noise during tests

# Run database migrations for tests
npm run migrate:test
```

## Test Categories

### 1. Unit Tests

Test individual functions and classes in isolation.

```typescript
import { TestAssertions } from '../framework/test-setup.js';
import { computeContentHash } from '../src/utils/deduplication.js';

describe('computeContentHash', () => {
  it('should generate consistent hash for same content', () => {
    const content = 'test content';
    const hash1 = computeContentHash(content);
    const hash2 = computeContentHash(content);

    TestAssertions.assertEquals(hash1, hash2, 'Hash should be consistent');
  });

  it('should generate different hashes for different content', () => {
    const hash1 = computeContentHash('content1');
    const hash2 = computeContentHash('content2');

    TestAssertions.assertNotEquals(hash1, hash2, 'Hashes should differ');
  });
});
```

### 2. Integration Tests

Test interactions between components.

```typescript
import { memoryStore } from '../src/services/memory-store.js';
import { memoryFind } from '../src/services/memory-find.js';

describe('Store and Find Integration', () => {
  it('should store and find knowledge items', async () => {
    const item = {
      kind: 'section',
      scope: { project: 'test' },
      data: {
        title: 'Test Section',
        heading: 'Test Section',
        body_md: '# Test Content',
      },
    };

    // Store the item
    const storeResult = await memoryStore([item]);
    TestAssertions.assert(storeResult.errors.length === 0, 'Store should succeed');

    // Find the item
    const findResult = await memoryFind({
      query: 'Test Section',
      types: ['section'],
    });

    TestAssertions.assert(findResult.hits.length > 0, 'Should find stored item');
    TestAssertions.assertEquals(findResult.hits[0].title, 'Test Section', 'Should find correct item');
  });
});
```

### 3. Performance Tests

Measure operation speed and resource usage.

```typescript
import { PerformanceTestHelper } from '../framework/helpers/performance-test-helper.js';

describe('Performance Tests', () => {
  let performanceHelper: PerformanceTestHelper;

  beforeEach(() => {
    performanceHelper = new PerformanceTestHelper();
  });

  it('should store single item within threshold', async () => {
    const { metrics } = await performanceHelper.measureOperation('store_single', async () => {
      const item = createTestSection();
      return memoryStore([item]);
    });

    TestAssertions.assertPerformance(metrics.duration, 100, 'Single item store');
    TestAssertions.assert(metrics.memoryDelta < 10, 'Memory usage should be reasonable');
  });
});
```

### 4. End-to-End Tests

Test complete user workflows.

```typescript
describe('Knowledge Management Workflow', () => {
  it('should handle complete knowledge lifecycle', async () => {
    // 1. Create knowledge items
    const section = createTestSection();
    const decision = createTestDecision();

    const storeResult = await memoryStore([section, decision]);
    TestAssertions.assert(storeResult.errors.length === 0, 'Should store all items');

    // 2. Search and find items
    const searchResult = await memoryFind({
      query: 'test',
      types: ['section', 'decision'],
    });
    TestAssertions.assert(searchResult.hits.length >= 2, 'Should find all items');

    // 3. Update items
    const updateItem = {
      ...section,
      data: {
        ...section.data,
        title: 'Updated Test Section',
      },
    };

    const updateResult = await memoryStore([updateItem]);
    TestAssertions.assert(updateResult.stored[0].status === 'updated', 'Should update item');

    // 4. Delete items
    const deleteResult = await softDelete(testDb, {
      entity_type: 'section',
      entity_id: storeResult.stored[0].id,
    });
    TestAssertions.assertEquals(deleteResult.status, 'deleted', 'Should delete item');
  });
});
```

## Writing Tests

### Test Structure

```typescript
import type { TestScenario } from '../framework/test-setup.js';

export const myTestScenario: TestScenario = {
  name: 'My Test Scenario',
  description: 'Description of what this scenario tests',
  setup: async (context: TestContext) => {
    // Optional setup code
    // Create test data, configure services, etc.
  },
  teardown: async (context: TestContext) => {
    // Optional cleanup code
    // Remove test data, reset state, etc.
  },
  tests: [
    {
      name: 'Specific Test Case',
      description: 'What this test case validates',
      timeout: 5000, // Optional timeout in milliseconds
      test: async (context: TestContext) => {
        // Test implementation
        // Use TestAssertions for validation
        TestAssertions.assert(condition, 'Description');
      },
    },
  ],
};
```

### Best Practices

1. **Use descriptive test names**
   ```typescript
   // Good
   it('should reject duplicate decisions with same title', async () => {});

   // Bad
   it('test duplicates', async () => {});
   ```

2. **Test one thing per test**
   ```typescript
   // Good
   it('should validate required fields', async () => {});
   it('should validate field formats', async () => {});

   // Bad
   it('should validate everything', async () => {});
   ```

3. **Use helper functions for setup**
   ```typescript
   const createTestSection = (overrides = {}) => ({
     kind: 'section',
     scope: { project: 'test' },
     data: {
       title: 'Test Section',
       heading: 'Test Section',
       body_md: '# Test Content',
       ...overrides,
     },
   });
   ```

4. **Test both success and failure cases**
   ```typescript
   it('should accept valid data', async () => {
     const result = await memoryStore([validItem]);
     TestAssertions.assert(result.errors.length === 0, 'Should accept valid data');
   });

   it('should reject invalid data', async () => {
     const result = await memoryStore([invalidItem]);
     TestAssertions.assert(result.errors.length > 0, 'Should reject invalid data');
   });
   ```

## Test Data Management

### TestDataFactory Usage

```typescript
import { TestDataFactory } from '../framework/helpers/test-data-factory.js';

const factory = new TestDataFactory();

// Create individual items
const section = factory.createSection();
const decision = factory.createDecision({
  title: 'Custom Decision',
  status: 'accepted',
});

// Create mixed batch
const batch = factory.createMixedBatch(50);

// Create edge cases
const edgeCases = factory.createEdgeCaseItems();
const { oversized, minimal, withSpecialCharacters } = edgeCases;
```

### Custom Test Data

```typescript
const createCustomSection = (overrides: Partial<SectionData> = {}) => ({
  kind: 'section',
  scope: { project: 'my-test', branch: 'test-branch' },
  data: {
    title: 'Custom Test Section',
    heading: 'Custom Test Section',
    body_md: '# Custom Content\n\nThis is custom test content.',
    tags: { category: 'test', priority: 'high' },
    ...overrides,
  },
  tags: { test: 'true', custom: 'section' },
});
```

## Performance Testing

### Setting Performance Thresholds

```typescript
const performanceHelper = new PerformanceTestHelper();

// Set custom thresholds
performanceHelper.setThreshold('custom_operation', 200);

// Run performance test
const { result, metrics } = await performanceHelper.measureOperation(
  'custom_operation',
  async () => {
    // Operation to measure
  },
  { itemCount: 10 }
);

// Verify performance
TestAssertions.assertPerformance(metrics.duration, 200, 'custom_operation');
```

### Performance Test Categories

1. **Single Operation Performance**
   ```typescript
   await performanceHelper.testMemoryStorePerformance(context);
   ```

2. **Batch Operation Performance**
   ```typescript
   await performanceHelper.testBatchOperations(context);
   ```

3. **Search Performance**
   ```typescript
   await performanceHelper.testMemoryFindPerformance(context);
   ```

4. **Scalability Testing**
   ```typescript
   await performanceHelper.testScalability(context);
   ```

5. **Load Testing**
   ```typescript
   await performanceHelper.testLoad(context);
   ```

### Performance Metrics

```typescript
const summary = performanceHelper.getPerformanceSummary();
console.log(`Average Duration: ${summary.averageDuration}ms`);
console.log(`Memory Usage: ${summary.averageMemoryUsed}MB`);
console.log(`Operations: ${summary.totalOperations}`);
```

## Database Testing

### Isolated Test Databases

```typescript
import { DatabaseTestHelper } from '../framework/helpers/database-test-helper.js';

// Create isolated test database
const testDb = await DatabaseTestHelper.setupTestDatabase('my-test-db');

try {
  // Run tests with isolated database
  await runTestsWithDatabase(testDb);
} finally {
  // Cleanup
  await DatabaseTestHelper.cleanupTestDatabase('my-test-db');
}
```

### Database Schema Verification

```typescript
const schema = await DatabaseTestHelper.verifySchema(pool);
console.log('Tables:', schema.tables);
console.log('Indexes:', schema.indexes);
console.log('Constraints:', schema.constraints);
```

### Data Seeding

```typescript
// Seed test data
const testData = [
  factory.createSection(),
  factory.createDecision(),
  factory.createIssue(),
];

for (const item of testData) {
  await memoryStore([item]);
}

// Verify data was seeded
const counts = await DatabaseTestHelper.getTableRowCounts(pool);
console.log('Table counts:', counts);
```

## Error Testing

### Error Test Scenarios

```typescript
import { ErrorTestHelper } from '../framework/helpers/error-test-helper.js';

const errorHelper = new ErrorTestHelper();

// Run all error tests
await errorHelper.runAllErrorTests(context);

// Get error handling metrics
const metrics = errorHelper.getErrorHandlingMetrics();
console.log(`Error Handling Rate: ${metrics.handlingRate}%`);
```

### Testing Specific Error Conditions

```typescript
// Test validation errors
await errorHelper.runErrorTest('validation_error', 'VALIDATION_FAILED', async () => {
  const invalidItem = { /* invalid data */ };
  const result = await memoryStore([invalidItem]);
  if (result.errors.length > 0) {
    throw new Error(result.errors[0].message);
  }
});

// Test immutability errors
await errorHelper.runErrorTest('immutability_violation', 'IMMUTABLE_ENTITY', async () => {
  const immutableItem = createAcceptedDecision();
  const result = await memoryStore([immutableItem]);
  if (result.errors.length > 0) {
    throw new Error(result.errors[0].message);
  }
});
```

### Error Recovery Testing

```typescript
// Test retry mechanisms
await errorHelper.testErrorRecovery(context);

// Test graceful degradation
await errorHelper.testGracefulDegradation(context);
```

## CI/CD Integration

### GitHub Actions Workflow

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: test
          POSTGRES_DB: cortex_memory_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
    - uses: actions/checkout@v3

    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
        cache: 'npm'

    - name: Install dependencies
      run: npm ci

    - name: Run database migrations
      run: npm run migrate:test
      env:
        DATABASE_URL: postgresql://postgres:test@localhost:5432/cortex_memory_test

    - name: Run tests
      run: npm test
      env:
        DATABASE_URL: postgresql://postgres:test@localhost:5432/cortex_memory_test
        NODE_ENV: test

    - name: Generate coverage report
      run: npm run test:coverage

    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
```

### Docker Testing

```dockerfile
FROM node:18-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci

# Copy source code
COPY . .

# Run database migrations
RUN npm run migrate:test

# Run tests
CMD ["npm", "test"]
```

### Test Configuration

```json
// package.json
{
  "scripts": {
    "test": "node --loader ts-node/esm tests/run-tests.ts",
    "test:watch": "node --loader ts-node/esm tests/run-tests.ts --watch",
    "test:coverage": "node --loader ts-node/esm tests/run-tests.ts --coverage",
    "test:unit": "node --loader ts-node/esm tests/unit/**/*.test.ts",
    "test:integration": "node --loader ts-node/esm tests/integration/**/*.test.ts",
    "test:performance": "node --loader ts-node/esm tests/performance/**/*.test.ts",
    "migrate:test": "node --loader ts-node/esm scripts/migrate-test.js"
  }
}
```

## Troubleshooting

### Common Test Issues

1. **Database Connection Errors**
   ```bash
   # Check PostgreSQL is running
   pg_isready -h localhost -p 5432

   # Check test database exists
   psql -h localhost -p 5432 -U postgres -l

   # Create test database
   createdb -h localhost -p 5432 -U postgres cortex_memory_test
   ```

2. **Timeout Issues**
   ```typescript
   // Increase timeout for slow tests
   it('slow operation', { timeout: 10000 }, async () => {
     // Test implementation
   });
   ```

3. **Memory Issues**
   ```bash
   # Increase Node.js memory limit
   NODE_OPTIONS="--max-old-space-size=4096" npm test
   ```

4. **Test Isolation**
   ```typescript
   // Ensure tests use isolated data
   beforeEach(async () => {
     await DatabaseTestHelper.clearTestData(pool);
   });
   ```

### Debugging Tests

1. **Enable verbose logging**
   ```bash
   LOG_LEVEL=debug npm test
   ```

2. **Run specific test**
   ```bash
   npm test -- --grep "specific test name"
   ```

3. **Debug with Node.js inspector**
   ```bash
   node --inspect-brk tests/run-tests.ts
   ```

### Test Performance Issues

1. **Identify slow tests**
   ```typescript
   const { metrics } = await performanceHelper.measureOperation('slow_test', async () => {
     // Test implementation
   });
   console.log(`Slow test took ${metrics.duration}ms`);
   ```

2. **Profile memory usage**
   ```typescript
   const memoryBefore = process.memoryUsage().heapUsed / 1024 / 1024;
   // Run test
   const memoryAfter = process.memoryUsage().heapUsed / 1024 / 1024;
   console.log(`Memory used: ${memoryAfter - memoryBefore}MB`);
   ```

3. **Database query optimization**
   ```sql
   EXPLAIN ANALYZE SELECT * FROM section WHERE title LIKE '%test%';
   ```

## Best Practices Summary

1. **Test Isolation**: Each test should be independent and not rely on other tests
2. **Clean Setup/Teardown**: Always clean up test data and state
3. **Descriptive Assertions**: Use clear assertion messages
4. **Edge Case Coverage**: Test boundary conditions and error cases
5. **Performance Monitoring**: Track operation performance and resource usage
6. **Error Testing**: Verify error handling and recovery mechanisms
7. **Data Variety**: Test with different data sizes and types
8. **Environment Consistency**: Ensure tests run consistently across environments

---

*For more detailed examples and advanced testing patterns, refer to the test files in the `tests/` directory.*