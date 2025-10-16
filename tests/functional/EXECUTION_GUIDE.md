# MCP Cortex Functional Test Execution Guide

Step-by-step guide for running complete functional tests before deploying to 20 users.

---

## Quick Start

```bash
# 1. Smoke test (5 minutes) - Run this first!
npm run test:smoke

# 2. Full functional tests (30 minutes)
npm run test:functional

# 3. Generate report
npm run test:report
```

---

## Prerequisites

### 1. Environment Setup

**Check server is running:**
```bash
wsl docker-compose ps
```

Expected output:
```
NAME                  STATUS              PORTS
cortex-postgres-1     Up 10 minutes       0.0.0.0:5433->5432/tcp
```

**Check connectivity:**
```powershell
Test-NetConnection -ComputerName localhost -Port 5433
```

**Check environment variables:**
```bash
echo $DATABASE_URL
# Should output: postgresql://cortex:[password]@[host]:5433/cortex_prod
```

If not set:
```bash
# Windows PowerShell
$env:DATABASE_URL="postgresql://cortex:trust@localhost:5433/cortex_prod"

# Mac/Linux
export DATABASE_URL="postgresql://cortex:trust@localhost:5433/cortex_prod"
```

### 2. Install Dependencies

```bash
cd D:\WORKSPACE\tools-node\mcp-cortex
npm install
```

### 3. Build TypeScript

```bash
npm run build
```

---

## Test Execution Phases

### Phase 1: Smoke Test (5 minutes) ⚡

**Purpose:** Quick validation of core functionality

```bash
npm run test:smoke
```

**What it tests:**
- ✅ TCP connection to database
- ✅ PostgreSQL authentication
- ✅ Simple query execution
- ✅ Store knowledge operation
- ✅ Find knowledge operation

**Success criteria:**
```
✅✅✅ ALL SMOKE TESTS PASSED ✅✅✅
Tests Passed: 5/5
```

**If smoke test fails:**
- DO NOT proceed to full tests
- Fix connectivity/configuration issues
- See [Troubleshooting](#troubleshooting) section

---

### Phase 2: Core Functionality Tests (15 minutes)

**Run connectivity tests:**
```bash
npm run test:functional -- tests/functional/01-connectivity.test.ts
```

**Expected results:**
- DB-001 through DB-005: All PASS
- Connection pool handles 10+ concurrent connections
- No crashes on pool exhaustion

**Run knowledge storage tests:**
```bash
npm run test:functional -- tests/functional/02-knowledge-storage.test.ts
```

**Expected results:**
- KS-001 through KS-013: All PASS
- All 9 knowledge types store correctly
- Validation errors handled gracefully

**Run knowledge retrieval tests:**
```bash
npm run test:functional -- tests/functional/03-knowledge-retrieval.test.ts
```

**Expected results:**
- KR-001 through KR-010: All PASS
- Fast/auto/deep modes work
- Scope and type filtering work
- Special characters handled safely

---

### Phase 3: Data Integrity Tests (10 minutes)

**Run deduplication tests:**
```bash
npm run test:functional -- tests/functional/04-deduplication.test.ts
```

**Expected results:**
- DD-001 through DD-005: All PASS
- Duplicates return existing ID
- Same content in different scopes stored separately

**Run immutability tests:**
```bash
npm run test:functional -- tests/functional/05-immutability.test.ts
```

**Expected results:**
- IM-001 through IM-008: All PASS
- Accepted ADRs cannot be modified
- Approved sections cannot be modified
- Appropriate errors returned

**Run scope isolation tests:**
```bash
npm run test:functional -- tests/functional/06-scope-isolation.test.ts
```

**Expected results:**
- SI-001 through SI-008: All PASS
- Projects isolated from each other
- Branches isolated from each other
- Cross-scope search works when intended

---

### Phase 4: Run All Tests Together (30 minutes)

**Full test suite:**
```bash
npm run test:functional
```

**With coverage:**
```bash
npm run test:functional:coverage
```

**Watch mode (for development):**
```bash
npm run test:functional:watch
```

---

## Understanding Test Output

### Success Output
```
✓ Category 1: Database Connectivity (5)
  ✓ DB-001: TCP Connection
  ✓ DB-002: PostgreSQL Authentication
  ✓ DB-003: Execute Simple Query
  ✓ DB-004: Connection Pool
  ✓ DB-005: Pool Exhaustion

Test Files  3 passed (3)
     Tests  45 passed (45)
  Duration  12.34s
```

### Failure Output
```
✓ Category 1: Database Connectivity (4)
  ✓ DB-001: TCP Connection
  ✓ DB-002: PostgreSQL Authentication
  ✗ DB-003: Execute Simple Query
    Expected: 1
    Received: undefined
  ✓ DB-004: Connection Pool
  ✓ DB-005: Pool Exhaustion

Test Files  1 failed | 2 passed (3)
     Tests  1 failed | 44 passed (45)
```

---

## Test Report Generation

### Generate HTML Report
```bash
npm run test:report
```

Opens browser with:
- Test results summary
- Coverage statistics
- Performance metrics
- Failure details

### Generate JSON Report
```bash
npm run test:functional -- --reporter=json > test-results.json
```

### Generate JUnit Report (for CI/CD)
```bash
npm run test:functional -- --reporter=junit > test-results.xml
```

---

## Test Data Cleanup

**Manual cleanup:**
```bash
# Connect to database
wsl docker-compose exec postgres psql -U cortex cortex_prod

# Delete test data
DELETE FROM knowledge WHERE scope->>'project' LIKE 'test-%';
DELETE FROM knowledge WHERE scope->>'project' = 'smoke-test';

# Verify
SELECT COUNT(*) FROM knowledge WHERE scope->>'project' LIKE 'test-%';
```

**Automated cleanup (in tests):**
All test files include `afterAll()` hooks that clean up test data automatically.

---

## Performance Benchmarking

### Measure Store Latency
```bash
npm run test:benchmark:store
```

Expected:
- P50: <100ms
- P95: <200ms
- P99: <500ms

### Measure Find Latency
```bash
npm run test:benchmark:find
```

Expected:
- Fast mode P95: <300ms
- Auto mode P95: <400ms
- Deep mode P95: <1000ms

### Load Test (20 concurrent users)
```bash
npm run test:load
```

Expected:
- All requests succeed
- No connection errors
- Latency within acceptable range

---

## Troubleshooting

### Smoke Test Failures

**TCP Connection Failed:**
```
❌ TCP connection failed: ECONNREFUSED
```

**Solution:**
```bash
# Check server running
wsl docker-compose ps

# Check port forwarding
netsh interface portproxy show v4tov4

# Restart if needed
wsl docker-compose restart
```

**Authentication Failed:**
```
❌ Authentication failed: password authentication failed
```

**Solution:**
```bash
# Check CONNECTION_INFO.txt for correct password
cat CONNECTION_INFO.txt

# Update DATABASE_URL
export DATABASE_URL="postgresql://cortex:CORRECT_PASSWORD@localhost:5433/cortex_prod"
```

### Test Timeouts

**Symptoms:**
```
✗ DB-003: Execute Simple Query
  Error: Timeout of 5000ms exceeded
```

**Solutions:**
1. Increase timeout in test file
2. Check database performance
3. Check network latency

### Connection Pool Exhausted

**Symptoms:**
```
✗ DB-004: Connection Pool
  Error: remaining connection slots are reserved
```

**Solutions:**
```typescript
// Increase pool size in DB_CONFIG
const DB_CONFIG = {
  max: 20, // Increase from 10
  idleTimeoutMillis: 30000,
};
```

### Memory Errors

**Symptoms:**
```
✗ Test suite failed to run
  JavaScript heap out of memory
```

**Solutions:**
```bash
# Increase Node.js memory
export NODE_OPTIONS="--max-old-space-size=4096"
npm run test:functional
```

---

## CI/CD Integration

### GitHub Actions Example

```yaml
# .github/workflows/test.yml
name: Functional Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:18-alpine
        env:
          POSTGRES_PASSWORD: test
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
          node-version: '20'

      - name: Install dependencies
        run: npm ci

      - name: Build
        run: npm run build

      - name: Run smoke test
        run: npm run test:smoke
        env:
          DATABASE_URL: postgresql://postgres:test@localhost:5432/postgres

      - name: Run functional tests
        run: npm run test:functional
        env:
          DATABASE_URL: postgresql://postgres:test@localhost:5432/postgres

      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

---

## Test Checklist

Use this checklist before deploying to production:

### Pre-Test
- [ ] Server is running
- [ ] Database is accessible
- [ ] Environment variables set
- [ ] Dependencies installed
- [ ] Code is built

### Smoke Test
- [ ] TCP connection: PASS
- [ ] Authentication: PASS
- [ ] Simple query: PASS
- [ ] Store knowledge: PASS
- [ ] Find knowledge: PASS

### Core Functionality
- [ ] All connectivity tests: PASS
- [ ] All storage tests: PASS
- [ ] All retrieval tests: PASS

### Data Integrity
- [ ] Deduplication: PASS
- [ ] Immutability: PASS
- [ ] Scope isolation: PASS

### Performance
- [ ] Store latency P95 < 300ms
- [ ] Find latency P95 < 500ms
- [ ] 20 concurrent users supported

### Final Steps
- [ ] Test report generated
- [ ] Known issues documented
- [ ] Test data cleaned up
- [ ] Ready for deployment

---

## Support

**For test failures:**
1. Check [TEST_PLAN.md](./TEST_PLAN.md) for test descriptions
2. Review [TROUBLESHOOTING.md](../../docs/TROUBLESHOOTING.md)
3. Check PostgreSQL logs: `wsl docker-compose logs postgres`
4. Contact development team with test report

**For CI/CD setup:**
- See examples in `.github/workflows/`
- Adjust for your CI platform (GitLab, Jenkins, etc.)

---

**Version:** 1.0.0
**Last Updated:** 2025-01-14
