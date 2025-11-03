# Phase 6 Integration Tests

Comprehensive integration test suite for the Cortex MCP project, focusing on realistic testing scenarios with Qdrant vector database operations, degraded path handling, document reassembly, and performance validation.

## Overview

Phase 6 integration tests verify the complete system functionality under various conditions:

1. **Happy Path Tests** - System operations when Qdrant is available
2. **Degraded Path Tests** - System resilience when Qdrant is unavailable
3. **Chunk Reassembly Tests** - Document reconstruction from chunks
4. **Performance Smoke Tests** - N=100 items, <1s target validation

## Test Structure

```
tests/integration/
├── qdrant-happy-path.test.ts      # Qdrant available scenarios
├── qdrant-degraded-path.test.ts   # Qdrant unavailable fallback
├── chunk-reassembly.test.ts       # Document reassembly validation
├── performance-smoke.test.ts      # Performance targets (N=100, <1s)
├── integration-test-runner.mjs    # Comprehensive test runner
└── README.md                      # This documentation
```

## Running Tests

### Quick Start

```bash
# Run complete Phase 6 integration test suite
npm run test:integration:phase6

# Run individual test categories
npm run test:integration:happy      # Qdrant happy path
npm run test:integration:degraded   # Degraded path
npm run test:integration:reassembly # Chunk reassembly
npm run test:integration:performance # Performance tests
```

### Manual Test Execution

```bash
# Using Vitest directly
npx vitest run --config vitest.integration.config.ts tests/integration/

# With coverage
npx vitest run --config vitest.coverage.config.ts tests/integration/ --coverage

# Watch mode for development
npx vitest --config vitest.integration.config.ts tests/integration/
```

### Custom Test Runner

```bash
# Run with comprehensive reporting and Qdrant detection
node tests/integration/integration-test-runner.mjs
```

## Test Categories

### 1. Happy Path Tests (`qdrant-happy-path.test.ts`)

Tests system functionality when Qdrant vector database is available and operational.

**Key Test Areas:**
- Basic memory operations (store/find)
- Mixed item type handling (entity, relation, decision, etc.)
- Advanced search functionality (semantic, hybrid, graph expansion)
- Chunking and document reassembly
- Performance and scalability (N=100 concurrent operations)
- Scope and isolation boundaries

**Success Criteria:**
- All CRUD operations succeed
- Vector search returns relevant results
- Chunk reassembly maintains content integrity
- Performance targets met (<1s for typical operations)

### 2. Degraded Path Tests (`qdrant-degraded-path.test.ts`)

Tests system resilience and graceful degradation when Qdrant is unavailable.

**Key Test Areas:**
- Degraded mode detection and fallback activation
- Storage operations with fallback mechanisms
- Keyword-based search as vector alternative
- Data consistency in degraded mode
- Error handling and recovery
- Performance without vector operations

**Success Criteria:**
- System detects Qdrant unavailability
- Fallback storage mechanisms activate
- Search functionality continues with keyword matching
- Data integrity maintained throughout degradation
- Performance remains acceptable without vectors

### 3. Chunk Reassembly Tests (`chunk-reassembly.test.ts`)

Tests the complete document chunking and reassembly pipeline.

**Key Test Areas:**
- Basic chunk reassembly (simple documents)
- Partial reassembly (missing chunks)
- Complex document handling (large, structured content)
- Metadata integrity through reassembly
- Special characters and encoding
- Edge cases and error handling
- Concurrent reassembly operations

**Success Criteria:**
- Documents are correctly chunked based on size/type
- Chunks preserve metadata and relationships
- Reassembly maintains content order and integrity
- Partial reassembly handles missing chunks gracefully
- Complex formatting and special characters preserved
- Performance remains acceptable for large documents

### 4. Performance Smoke Tests (`performance-smoke.test.ts`)

Lightweight performance tests verifying system meets performance targets.

**Performance Targets:**
- **N=100 items storage:** <1 second
- **Single query search:** <200ms
- **10 concurrent searches:** <1.5 seconds
- **Mixed operations (100 total):** <2 seconds
- **Memory usage:** <100MB increase for test dataset

**Key Test Areas:**
- Storage performance (batch operations)
- Search performance (various query types)
- Concurrent operation handling
- Memory and resource usage
- Performance regression detection
- Scope-isolated operations

**Success Criteria:**
- All operations complete within target times
- Memory usage remains within acceptable limits
- Performance regressions detected and reported
- System scales with increasing load

## Test Data and Scenarios

### Realistic Data Patterns

Tests use realistic data that mirrors actual usage patterns:

**Knowledge Item Types:**
- `entity`: System components, services, concepts
- `relation`: Dependencies, associations, connections
- `decision`: Technical decisions, architectural choices
- `observation`: Metrics, findings, measurements
- `risk`: Risk assessments, mitigation strategies
- `assumption`: Working assumptions, dependencies
- `runbook`: Procedures, troubleshooting guides
- `section`: Documentation sections, specifications

**Content Characteristics:**
- Technical documentation with formatting
- Code examples and configuration snippets
- Performance metrics and measurements
- Security and compliance information
- Multilingual and special character content
- Large documents (>10,000 characters)

### Scope Isolation

Tests verify proper scope-based data isolation:

```javascript
// Example scope structure
scope: {
  project: 'project-name',
  branch: 'feature-branch',
  org: 'organization-name'
}
```

## Environment Setup

### Prerequisites

1. **Node.js** >= 20.0.0
2. **TypeScript** configured
3. **Vitest** test framework
4. **Qdrant** (optional - tests work with fallback)

### Qdrant Setup (Optional)

For full happy path testing:

```bash
# Using Docker
docker run -p 6333:6333 qdrant/qdrant:latest

# Or using WSL2
wsl -d Ubuntu docker run -p 6333:6333 qdrant/qdrant:latest
```

**Environment Variables:**
```bash
QDRANT_URL=http://localhost:6333
QDRANT_API_KEY=your-api-key-optional
```

### Test Configuration

The test suite automatically detects Qdrant availability and adjusts testing accordingly:

- **Qdrant Available:** Full integration tests with vector operations
- **Qdrant Unavailable:** Degraded path tests with fallback mechanisms

## Test Results and Reporting

### Expected Output

Successful test run produces:

```
🎉 All Integration Tests Passed!
Phase 6 testing completed successfully
System verified for:
  • Qdrant happy path operations
  • Qdrant degraded path fallback
  • Document chunk reassembly
  • Performance targets (N=100, <1s)
```

### Performance Metrics

Tests report detailed performance metrics:

```
Storage Performance: 100 items in 850ms (8.50ms per item)
Storage Rate: 117 items/second
Search Performance Results:
  Query "authentication security": 125ms, 3 results
  Query "database performance": 98ms, 2 results
Average search time: 111.50ms
```

### Coverage Reports

Generate coverage with:

```bash
npm run test:integration:performance -- --coverage
```

Coverage reports saved to `coverage/` directory.

## Troubleshooting

### Common Issues

**Qdrant Connection Errors:**
```bash
# Check if Qdrant is running
curl http://localhost:6333/health

# Start Qdrant if needed
docker run -p 6333:6333 qdrant/qdrant:latest
```

**Test Timeouts:**
```bash
# Increase timeout in vitest.config.ts
testTimeout: 120000, // 2 minutes
```

**Memory Issues:**
```bash
# Run tests with increased Node.js memory
node --max-old-space-size=4096 node_modules/.bin/vitest run tests/integration/
```

### Debug Mode

Run tests with verbose output:

```bash
DEBUG=cortex:* npm run test:integration:phase6
```

### Fallback Mode

If Qdrant is unavailable, tests automatically use fallback mode:

```
⚠️  Qdrant is not available - tests will use fallback mode
```

This is expected behavior and validates the degraded path functionality.

## Best Practices

### Test Development

1. **Use realistic data** that mirrors actual usage patterns
2. **Test both success and failure** scenarios
3. **Verify performance targets** with timing assertions
4. **Include edge cases** like special characters and large content
5. **Test scope isolation** to prevent data leakage

### Performance Testing

1. **Warm up the system** before measuring performance
2. **Run multiple iterations** for consistent measurements
3. **Monitor memory usage** during intensive operations
4. **Test concurrent operations** for thread safety
5. **Establish baselines** for regression detection

### CI/CD Integration

```yaml
# Example GitHub Actions
- name: Run Phase 6 Integration Tests
  run: npm run test:integration:phase6
  env:
    QDRANT_URL: ${{ secrets.QDRANT_URL }}
    QDRANT_API_KEY: ${{ secrets.QDRANT_API_KEY }}
```

## Contributing

### Adding New Tests

1. Create test file in `tests/integration/`
2. Follow naming convention: `category-description.test.ts`
3. Include performance targets where applicable
4. Add test runner script entry if needed
5. Update documentation

### Test Categories

- **Unit Tests:** Individual component testing (`tests/unit/`)
- **Integration Tests:** System component interaction (`tests/integration/`)
- **E2E Tests:** Full system validation (`tests/e2e/`)
- **Performance Tests:** Load and stress testing (`tests/performance/`)

### Quality Standards

- All tests must pass consistently
- Performance targets must be met
- Code coverage should be >80%
- Tests should be deterministic and repeatable
- Documentation must be kept current

## Performance Benchmarks

### Current Baselines (as of Phase 6)

| Operation | Target | Actual | Status |
|-----------|--------|--------|--------|
| Store 100 items | <1000ms | ~850ms | ✅ |
| Single search | <200ms | ~110ms | ✅ |
| 10 concurrent searches | <1500ms | ~1200ms | ✅ |
| Mixed 50 operations | <2000ms | ~1600ms | ✅ |
| Memory increase (100 items) | <100MB | ~45MB | ✅ |

### Regression Detection

Performance regression testing automatically detects:
- Storage operation slowdowns (>150% baseline)
- Search performance degradation (>150% baseline)
- Memory usage increases (>200% baseline)
- Concurrent operation bottlenecks

## Future Enhancements

### Planned Test Additions

1. **Load Testing:** Higher volume tests (N=1000, N=10000)
2. **Stress Testing:** System limit validation
3. **Multi-region Testing:** Distributed system behavior
4. **Chaos Engineering:** Failure injection testing
5. **Security Testing:** Vulnerability scanning

### Performance Improvements

1. **Parallel Test Execution:** Concurrent test running
2. **Test Data Caching:** Reusable test datasets
3. **Mock Service Optimization:** Faster test setup
4. **Performance Profiling:** Detailed performance analysis

---

**Phase 6 Integration Tests** provide comprehensive validation of the Cortex MCP system's functionality, performance, and resilience under various operating conditions.