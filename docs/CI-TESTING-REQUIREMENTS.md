# CI Testing Requirements and Mandatory Profile

This document defines the mandatory testing profile for Continuous Integration (CI) environments in the mcp-cortex project.

## Overview

The CI testing profile ensures:

- **Fast execution**: Tests run quickly in CI environments
- **Reliable results**: No flaky tests due to external dependencies
- **Consistent behavior**: Predictable test execution and results
- **High coverage**: Comprehensive test coverage for critical code paths
- **Clean isolation**: Tests don't interfere with each other

## Test Categories and Requirements

### 1. Unit Tests (Primary CI Focus)

**Purpose**: Test individual functions and classes in isolation

**Requirements**:

- ✅ Must run in under 100ms per test
- ✅ All external services mocked
- ✅ No network calls to external services
- ✅ Deterministic results (no random failures)
- ✅ 90%+ coverage for core utilities
- ✅ 80%+ coverage for services

**Files**: `tests/unit/**/*.test.ts`

**Mock Profile**: Use comprehensive mocks from `tests/mocks/`

### 2. Integration Tests (Secondary CI Focus)

**Purpose**: Test interactions between components

**Requirements**:

- ✅ Use in-memory databases or test containers
- ✅ Maximum 5 second timeout per test
- ✅ Clean up all resources after each test
- ✅ Deterministic setup and teardown
- ✅ 75%+ coverage for integration paths

**Files**: `tests/integration/**/*.test.ts`

### 3. Performance Tests (Separate Execution)

**Purpose**: Validate performance characteristics

**Requirements**:

- ⚠️ Run separately from unit/integration tests
- ⚠️ Use realistic data sizes
- ⚠️ Include baseline measurements
- ⚠️ Run only on performance branches

**Files**: `tests/performance/**/*.test.ts`

### 4. Security Tests (Separate Execution)

**Purpose**: Validate security measures

**Requirements**:

- ⚠️ Test authentication and authorization
- ⚠️ Validate input sanitization
- ⚠️ Check for common vulnerabilities
- ⚠️ Run in isolated environment

**Files**: `tests/security/**/*.test.ts`

## Mandatory Mocking Profile

### External Services

All external services MUST be mocked in CI:

```typescript
// Database
vi.doMock('../../src/db/unified-database-layer-v2', () => ({
  UnifiedDatabaseLayerV2: vi.fn().mockImplementation(() => mockDatabase),
}));

// Embeddings
vi.doMock('../../src/services/embeddings/embedding-service', () => ({
  EmbeddingService: vi.fn().mockImplementation(() => mockEmbeddings),
}));

// Qdrant
vi.doMock('../../src/db/qdrant-client', () => ({
  qdrant: mockQdrant,
}));
```

### Environment Variables

Critical environment variables for CI:

```bash
NODE_ENV=test
CI=true
DISABLE_EXTERNAL_APIS=true
MOCK_EMBEDDINGS=true
DATABASE_URL=memory://test
EXTERNAL_SERVICE_TIMEOUT=1000
```

### Mock Data Requirements

**Embeddings**: Must be deterministic and reproducible

```typescript
const generateMockEmbedding = (text: string): number[] => {
  const hash = text.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
  return Array.from({ length: 1536 }, (_, i) => (Math.sin((hash + i) * 0.1) + 1) * 0.5);
};
```

**Database**: Must use in-memory or mocked implementations

- No persistence required between tests
- Fast setup and teardown
- Consistent behavior across test runs

## Coverage Requirements

### Global Thresholds

- **Statements**: 80%
- **Branches**: 75%
- **Functions**: 80%
- **Lines**: 80%

### Critical Path Thresholds

- **Services**: 85%
- **Core Utilities**: 90%
- **Authentication**: 95%
- **Database Operations**: 90%

### Exclusions

- Type definition files (`src/types/**`)
- Configuration files (`src/constants/**`)
- Test files themselves
- Main entry point with side effects

## Test Execution Order

### 1. Unit Tests (Fastest)

```bash
npm run test:unit
```

### 2. Integration Tests (Slower)

```bash
npm run test:integration
```

### 3. Coverage Report

```bash
npm run test:coverage
```

### 4. Coverage Check (Gate)

```bash
npm run verify-test-coverage
```

## CI Configuration Files

### Vitest CI Config (`vitest.ci.config.ts`)

- Single-threaded execution
- Isolated test environment
- Strict timeouts
- Comprehensive coverage settings
- JUnit output for CI integrations

### Global Setup (`tests/setup/global-setup.ts`)

- Initialize test environment
- Setup global mocks
- Configure test database
- Generate test run ID

### Per-Test Setup (`tests/setup/test-setup.ts`)

- Reset mocks before each test
- Generate consistent test data
- Setup service mocks
- Cleanup after each test

## Test Data Management

### Sample Data

Use deterministic sample data:

```typescript
const sampleKnowledgeItems = [
  {
    id: 'test-entity-1',
    kind: 'entity',
    scope: { project: 'test-project' },
    data: { content: 'Test content' },
  },
  // ... more items
];
```

### Data Factories

Use factory patterns for test data:

```typescript
export const createMockKnowledgeItem = (overrides = {}) => ({
  id: 'test-id',
  kind: 'entity',
  scope: { project: 'test' },
  data: { content: 'test content' },
  ...overrides,
});
```

## Error Handling in Tests

### Expected Errors

```typescript
// Test expected error scenarios
expect(() => service.validate(invalidData)).toThrow('Validation failed');
```

### Mock Errors

```typescript
// Simulate external service errors
vi.mocked(mockDatabase.store).mockRejectedValue(new Error('Database connection failed'));
```

## Performance Requirements

### Test Execution Speed

- Unit tests: < 100ms each
- Integration tests: < 5s each
- Total test suite: < 5 minutes

### Resource Usage

- Memory: < 512MB per test process
- CPU: Minimal CPU usage
- Network: No external network calls

## Quality Gates

### Pre-commit Hooks

```bash
# Run in .husky/pre-commit
npm run type-check
npm run lint
npm run test:unit
npm run verify-test-coverage
```

### CI Pipeline Gates

```bash
# Run in CI pipeline
npm run type-check
npm run lint
npm run test:unit
npm run test:integration
npm run test:coverage
npm run verify-test-coverage
```

## Reporting

### Test Results

- JSON output for CI integrations
- JUnit XML for test reporting systems
- Console output for developers
- Coverage reports (HTML, JSON, LCOV)

### Coverage Reports

- Stored in `coverage/` directory
- Uploaded to coverage services
- Included in CI artifacts

## Troubleshooting

### Common Issues

1. **Flaky Tests**: Check for async timing issues
2. **Memory Leaks**: Verify cleanup in teardown
3. **Slow Tests**: Mock external dependencies
4. **Coverage Gaps**: Add tests for missing paths

### Debug Mode

```bash
# Run with verbose output
npm run test:unit -- --reporter=verbose

# Run specific test file
npm run test:unit path/to/test.test.ts

# Run with debugging
npm run test:unit -- --inspect
```

## Maintenance

### Regular Tasks

- Update mock implementations when APIs change
- Review and adjust coverage thresholds
- Update sample data as features evolve
- Monitor test execution times

### When Adding New Features

1. Create comprehensive unit tests
2. Add appropriate mocks
3. Update coverage requirements
4. Verify CI pipeline passes
5. Update documentation as needed

---

**This profile ensures that every commit is validated by a comprehensive, fast, and reliable test suite before being merged into the main branch.**
