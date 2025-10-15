# MCP Cortex Functional Tests

Complete functional test suite for validating MCP Cortex before multi-user deployment.

---

## Quick Start

```bash
# 1. Start with smoke test (5 min)
npm run test:smoke

# 2. If smoke test passes, run full suite (30 min)
npm run test:functional

# 3. Review results
npm run test:report
```

---

## Test Suite Overview

### Test Categories

| Category | Tests | Priority | Duration |
|----------|-------|----------|----------|
| 1. Database Connectivity | 5 | P0 (CRITICAL) | 2 min |
| 2. Knowledge Storage | 13 | P0 (CRITICAL) | 5 min |
| 3. Knowledge Retrieval | 10 | P0 (CRITICAL) | 5 min |
| 4. Deduplication | 5 | P1 (HIGH) | 3 min |
| 5. Immutability | 8 | P1 (HIGH) | 3 min |
| 6. Scope Isolation | 8 | P1 (HIGH) | 3 min |
| 7. Error Handling | 8 | P2 (MEDIUM) | 3 min |
| 8. Performance | 8 | P2 (MEDIUM) | 5 min |
| **TOTAL** | **65** | | **~30 min** |

### Coverage

- ✅ **9 Knowledge Types:** section, runbook, change, issue, decision, todo, release_note, ddl, pr_context
- ✅ **3 Search Modes:** fast, auto, deep
- ✅ **Scope Isolation:** project, branch, org
- ✅ **Data Integrity:** deduplication, immutability
- ✅ **Error Handling:** validation, SQL injection, special characters
- ✅ **Performance:** latency, concurrency, load

---

## Files

```
tests/functional/
├── README.md                         # This file
├── TEST_PLAN.md                      # Detailed test scenarios (65 tests)
├── EXECUTION_GUIDE.md                # Step-by-step execution guide
│
├── run-smoke-test.ts                 # Quick 5-minute smoke test
├── 01-connectivity.test.ts           # Database connectivity (5 tests)
├── 02-knowledge-storage.test.ts      # Storage operations (13 tests)
└── 03-knowledge-retrieval.test.ts    # Search operations (10 tests)
```

---

## Usage

### Smoke Test (Run First!)

```bash
npm run test:smoke
```

**Output:**
```
═══════════════════════════════════════════════════════════
 MCP CORTEX SMOKE TEST
═══════════════════════════════════════════════════════════

[1/5] TCP CONNECTION
✅ TCP connection successful

[2/5] AUTHENTICATION
✅ PostgreSQL authentication successful

[3/5] SIMPLE QUERY
✅ Query executed: PostgreSQL 18.0

[4/5] STORE KNOWLEDGE
✅ Knowledge stored with ID: uuid-here

[5/5] FIND KNOWLEDGE
✅ Found 1 result(s) in 45ms

═══════════════════════════════════════════════════════════
 SUMMARY
═══════════════════════════════════════════════════════════

Tests Passed: 5/5
Tests Failed: 0/5

✅✅✅ ALL SMOKE TESTS PASSED ✅✅✅
```

### Full Functional Tests

```bash
# Run all tests
npm run test:functional

# Run specific category
npm run test:functional -- tests/functional/01-connectivity.test.ts

# Run with coverage
npm run test:functional:coverage

# Watch mode
npm run test:functional:watch
```

### Generate Report

```bash
npm run test:report
```

Opens HTML report with:
- Pass/fail summary
- Coverage statistics
- Performance metrics
- Failure details

---

## Test Configuration

### Environment Variables

```bash
# Required
DATABASE_URL="postgresql://cortex:password@localhost:5433/cortex_prod"

# Optional
NODE_ENV="test"
LOG_LEVEL="error"
```

### Test Scope

Tests use isolated scope to avoid conflicts:

```typescript
const TEST_SCOPE = {
  org: 'test-org',
  project: 'test-project',
  branch: 'test-branch',
};
```

All test data is automatically cleaned up after tests complete.

---

## Success Criteria

### Smoke Test
- **PASS:** All 5 tests pass
- **FAIL:** Any test fails → Fix before proceeding

### Full Test Suite
- **PASS:** ≥90% of P0 tests pass, ≥85% of P1 tests pass
- **PASS WITH WARNINGS:** ≥80% overall, known issues documented
- **FAIL:** <80% pass rate or any critical (P0) failures

### Performance
- Store latency P95: <300ms
- Find latency P95: <500ms
- 20 concurrent users supported

---

## Troubleshooting

### Common Issues

**1. Connection refused**
```bash
# Check server is running
wsl docker-compose ps

# Restart if needed
wsl docker-compose restart
```

**2. Authentication failed**
```bash
# Check password in CONNECTION_INFO.txt
# Update DATABASE_URL with correct password
```

**3. Tests timeout**
```bash
# Increase Node memory
export NODE_OPTIONS="--max-old-space-size=4096"
```

**4. Port already in use**
```bash
# Check what's using port 5433
netstat -ano | findstr :5433

# Kill process or change port
```

See [EXECUTION_GUIDE.md](./EXECUTION_GUIDE.md) for detailed troubleshooting.

---

## Development

### Adding New Tests

1. Create test file: `XX-category.test.ts`
2. Follow existing structure:
   ```typescript
   describe('Category X: Name', () => {
     describe('TEST-ID: Description', () => {
       it('should do something', async () => {
         // Test implementation
       });
     });
   });
   ```
3. Add to TEST_PLAN.md
4. Update this README

### Running Single Test

```bash
npm run test:functional -- -t "DB-001"
```

### Debug Mode

```bash
npm run test:functional -- --inspect-brk
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run Smoke Test
  run: npm run test:smoke

- name: Run Full Tests
  run: npm run test:functional

- name: Upload Coverage
  uses: codecov/codecov-action@v3
```

See [EXECUTION_GUIDE.md](./EXECUTION_GUIDE.md) for complete CI/CD examples.

---

## Test Reports

### HTML Report
- Location: `coverage/index.html`
- Contains: Coverage, test results, performance metrics

### JSON Report
```bash
npm run test:functional -- --reporter=json > test-results.json
```

### JUnit Report (for CI)
```bash
npm run test:functional -- --reporter=junit > test-results.xml
```

---

## Performance Baselines

### Expected Latencies

| Operation | P50 | P95 | P99 |
|-----------|-----|-----|-----|
| Store single item | <50ms | <100ms | <200ms |
| Store batch (10) | <200ms | <500ms | <1s |
| Find (fast mode) | <100ms | <300ms | <500ms |
| Find (deep mode) | <300ms | <1s | <2s |

### Load Test Results

| Scenario | Users | Success Rate | Avg Latency |
|----------|-------|--------------|-------------|
| Light load | 10 | 100% | <200ms |
| Normal load | 20 | 100% | <300ms |
| Heavy load | 50 | 98% | <500ms |

---

## Documentation

- **[TEST_PLAN.md](./TEST_PLAN.md)** - Complete test plan with 65 test scenarios
- **[EXECUTION_GUIDE.md](./EXECUTION_GUIDE.md)** - Step-by-step execution guide
- **[../../docs/TROUBLESHOOTING.md](../../docs/TROUBLESHOOTING.md)** - General troubleshooting

---

## Support

**For test failures:**
1. Check [EXECUTION_GUIDE.md](./EXECUTION_GUIDE.md) troubleshooting section
2. Review PostgreSQL logs: `wsl docker-compose logs postgres`
3. Run diagnostic: `node ../../scripts/installation/client/test-connection.js`
4. Contact development team with test report

---

**Version:** 1.0.0
**Last Updated:** 2025-01-14
**Maintained By:** MCP Cortex Team
