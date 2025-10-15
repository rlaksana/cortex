# MCP Cortex Functional Test Plan

Complete functional testing before multi-user deployment.

---

## Test Objectives

1. **Verify Core Functionality** - All knowledge operations work correctly
2. **Validate Data Integrity** - Deduplication, immutability, scope isolation
3. **Test Error Handling** - Graceful failures, clear error messages
4. **Assess Performance** - Response times under load
5. **Confirm Multi-User Support** - Concurrent access, connection pooling

---

## Test Environment

### Configuration
- **Server:** Windows 11 Build 26200, WSL 2.6.1.0
- **Database:** PostgreSQL 18 Alpine (Docker)
- **Network:** NAT mode with port forwarding
- **Connection:** postgresql://cortex:[password]@10.10.254.177:5433/cortex_prod

### Test Data Scope
```json
{
  "org": "test-org",
  "project": "mcp-cortex",
  "branch": "test-functional"
}
```

---

## Test Categories

### Category 1: Database Connectivity (CRITICAL)
**Priority:** P0 - Must pass before proceeding

| Test ID | Scenario | Expected Result |
|---------|----------|-----------------|
| DB-001 | TCP connection to server | Connection successful |
| DB-002 | PostgreSQL authentication | Auth successful |
| DB-003 | Execute simple query | Query executes, returns result |
| DB-004 | Connection pool (10 concurrent) | All connections succeed |
| DB-005 | Connection pool exhaustion | Queues properly, no crashes |

### Category 2: Knowledge Storage (CRITICAL)
**Priority:** P0 - Core functionality

| Test ID | Scenario | Expected Result |
|---------|----------|-----------------|
| KS-001 | Store section (basic) | Returns stored item with ID |
| KS-002 | Store runbook | Returns stored item |
| KS-003 | Store change | Returns stored item |
| KS-004 | Store issue | Returns stored item |
| KS-005 | Store decision (ADR) | Returns stored item |
| KS-006 | Store todo | Returns stored item |
| KS-007 | Store release_note | Returns stored item |
| KS-008 | Store ddl | Returns stored item |
| KS-009 | Store pr_context | Returns stored item |
| KS-010 | Store with tags | Tags persisted correctly |
| KS-011 | Store without optional fields | Uses defaults |
| KS-012 | Store invalid kind | Returns error |
| KS-013 | Store missing required fields | Returns validation error |

### Category 3: Knowledge Retrieval (CRITICAL)
**Priority:** P0 - Core functionality

| Test ID | Scenario | Expected Result |
|---------|----------|-----------------|
| KR-001 | Find by query (fast mode) | Returns relevant results |
| KR-002 | Find by query (auto mode) | Returns relevant results |
| KR-003 | Find by query (deep mode) | Returns fuzzy matches |
| KR-004 | Find with scope filter | Returns only matching scope |
| KR-005 | Find with type filter | Returns only specified types |
| KR-006 | Find with top_k=1 | Returns 1 result |
| KR-007 | Find with top_k=50 | Returns up to 50 results |
| KR-008 | Find no results | Returns empty array with suggestions |
| KR-009 | Find with special characters | Handles correctly |
| KR-010 | Find with very long query | Handles gracefully |

### Category 4: Deduplication (HIGH)
**Priority:** P1 - Data integrity

| Test ID | Scenario | Expected Result |
|---------|----------|-----------------|
| DD-001 | Store identical content twice | Second returns existing ID |
| DD-002 | Store same content, different scope | Both stored (different scopes) |
| DD-003 | Store same content, different tags | Returns existing ID |
| DD-004 | Store 100 duplicates | All return same ID |
| DD-005 | Hash collision handling | Graceful error or retry |

### Category 5: Immutability (HIGH)
**Priority:** P1 - Data integrity

| Test ID | Scenario | Expected Result |
|---------|----------|-----------------|
| IM-001 | Update ADR (status='proposed') | Update succeeds |
| IM-002 | Update ADR (status='accepted') | Returns immutability error |
| IM-003 | Update accepted ADR title | Returns immutability error |
| IM-004 | Update accepted ADR rationale | Returns immutability error |
| IM-005 | Update accepted ADR alternatives | Returns immutability error |
| IM-006 | Update section (approved=false) | Update succeeds |
| IM-007 | Update section (approved=true) body | Returns immutability error |
| IM-008 | Update approved section tags | Update succeeds (tags mutable) |

### Category 6: Scope Isolation (HIGH)
**Priority:** P1 - Multi-user safety

| Test ID | Scenario | Expected Result |
|---------|----------|-----------------|
| SI-001 | Store in project A, find in project A | Found |
| SI-002 | Store in project A, find in project B | Not found |
| SI-003 | Store in branch A, find in branch A | Found |
| SI-004 | Store in branch A, find in branch B | Not found |
| SI-005 | Store with org, find with same org | Found |
| SI-006 | Store with org A, find with org B | Not found |
| SI-007 | Cross-branch search (omit branch) | Found across branches |
| SI-008 | Cross-project search (omit project) | Found across projects |

### Category 7: Error Handling (MEDIUM)
**Priority:** P2 - User experience

| Test ID | Scenario | Expected Result |
|---------|----------|-----------------|
| EH-001 | Invalid JSON payload | Returns parse error |
| EH-002 | Missing required field | Returns validation error with field name |
| EH-003 | Invalid kind value | Returns enum validation error |
| EH-004 | Invalid scope format | Returns validation error |
| EH-005 | Database connection lost | Returns connection error |
| EH-006 | Query timeout | Returns timeout error |
| EH-007 | Malformed query string | Returns error, doesn't crash |
| EH-008 | SQL injection attempt | Sanitized, returns safe error |

### Category 8: Performance (MEDIUM)
**Priority:** P2 - User experience

| Test ID | Scenario | Expected | Measurement |
|---------|----------|----------|-------------|
| PF-001 | Store single item | <100ms | P50 latency |
| PF-002 | Store 100 items batch | <2s | Total time |
| PF-003 | Find query (fast mode) | <300ms | P95 latency |
| PF-004 | Find query (deep mode) | <1s | P95 latency |
| PF-005 | 10 concurrent stores | <500ms each | P95 latency |
| PF-006 | 20 concurrent finds | <500ms each | P95 latency |
| PF-007 | Database size 1000 items | <300ms find | P95 latency |
| PF-008 | Database size 10000 items | <500ms find | P95 latency |

### Category 9: Load Testing (LOW)
**Priority:** P3 - Capacity planning

| Test ID | Scenario | Expected Result |
|---------|----------|-----------------|
| LT-001 | 20 users, 10 req/min each | All succeed |
| LT-002 | 20 users, sustained 1 hour | No degradation |
| LT-003 | Connection pool stress (100 conn) | Queues properly |
| LT-004 | Memory usage under load | <2GB |
| LT-005 | CPU usage under load | <80% |

---

## Test Execution Order

### Phase 1: Smoke Tests (5 minutes)
**Goal:** Verify basic functionality before detailed testing

1. DB-001: TCP connection
2. DB-002: Authentication
3. DB-003: Simple query
4. KS-001: Store section
5. KR-001: Find query

**Pass Criteria:** All 5 tests pass

### Phase 2: Core Functionality (15 minutes)
**Goal:** Test all knowledge types and operations

1. All KS-* tests (Knowledge Storage)
2. All KR-* tests (Knowledge Retrieval)
3. All DD-* tests (Deduplication)

**Pass Criteria:** 95% pass rate (1-2 failures acceptable)

### Phase 3: Data Integrity (10 minutes)
**Goal:** Verify immutability and scope isolation

1. All IM-* tests (Immutability)
2. All SI-* tests (Scope Isolation)

**Pass Criteria:** 100% pass rate (data integrity is critical)

### Phase 4: Robustness (10 minutes)
**Goal:** Test error handling and edge cases

1. All EH-* tests (Error Handling)
2. Selected edge cases

**Pass Criteria:** All errors handled gracefully, no crashes

### Phase 5: Performance (20 minutes)
**Goal:** Measure performance under realistic load

1. All PF-* tests (Performance)
2. Selected LT-* tests (Load Testing)

**Pass Criteria:** 90% of tests meet performance targets

---

## Test Data Templates

### Section Template
```json
{
  "kind": "section",
  "scope": {"project": "test-project", "branch": "test-branch"},
  "data": {
    "title": "Test Section",
    "body_md": "# Test\nThis is test content",
    "document_id": "doc-001"
  },
  "tags": {"category": "test"}
}
```

### Decision (ADR) Template
```json
{
  "kind": "decision",
  "scope": {"project": "test-project", "branch": "test-branch"},
  "data": {
    "component": "test-component",
    "status": "proposed",
    "title": "Test ADR",
    "rationale": "Testing ADR functionality",
    "alternatives_considered": ["Alt 1", "Alt 2"]
  }
}
```

### Issue Template
```json
{
  "kind": "issue",
  "scope": {"project": "test-project", "branch": "test-branch"},
  "data": {
    "subject_ref": "test-issue-001",
    "severity": "medium",
    "status": "open",
    "root_cause": "Test root cause",
    "resolution": "Test resolution",
    "tracker": "github"
  }
}
```

---

## Pass/Fail Criteria

### Overall Test Suite
- **PASS:** ≥90% of P0 tests pass, ≥85% of P1 tests pass, ≥70% of P2 tests pass
- **FAIL:** Any P0 test fails, or <80% overall pass rate

### Individual Test
- **PASS:** Expected result matches actual result
- **FAIL:** Expected result does not match actual result
- **BLOCKED:** Test cannot run due to prerequisite failure
- **SKIP:** Test intentionally skipped (document reason)

### Performance Test
- **PASS:** Latency within expected range
- **WARN:** Latency 10-50% above expected
- **FAIL:** Latency >50% above expected

---

## Test Execution Checklist

### Pre-Test Setup
- [ ] Server is running (`wsl docker-compose ps`)
- [ ] Database is accessible (`Test-NetConnection -Port 5433`)
- [ ] Test database is clean or backed up
- [ ] Test scripts are executable
- [ ] Environment variables set correctly

### During Testing
- [ ] Document all failures with screenshots/logs
- [ ] Note performance metrics
- [ ] Monitor resource usage (CPU, memory, disk)
- [ ] Check for error messages in PostgreSQL logs

### Post-Test
- [ ] Generate test report
- [ ] Analyze failures
- [ ] Document known issues
- [ ] Clean up test data
- [ ] Archive logs

---

## Test Report Template

```
MCP CORTEX FUNCTIONAL TEST REPORT
==================================

Test Date: [YYYY-MM-DD]
Tester: [Name]
Environment: [Production/Staging/Test]
Database: [IP:Port]

SUMMARY
-------
Total Tests: [X]
Passed: [X] ([X]%)
Failed: [X] ([X]%)
Blocked: [X]
Skipped: [X]

RESULTS BY CATEGORY
-------------------
Database Connectivity: [X/X] ([X]%)
Knowledge Storage: [X/X] ([X]%)
Knowledge Retrieval: [X/X] ([X]%)
Deduplication: [X/X] ([X]%)
Immutability: [X/X] ([X]%)
Scope Isolation: [X/X] ([X]%)
Error Handling: [X/X] ([X]%)
Performance: [X/X] ([X]%)

CRITICAL FAILURES
-----------------
[List any P0 test failures]

KNOWN ISSUES
------------
[List known issues found during testing]

PERFORMANCE METRICS
-------------------
Store latency (P50): [X]ms
Store latency (P95): [X]ms
Find latency (P50): [X]ms
Find latency (P95): [X]ms
Concurrent users supported: [X]

RECOMMENDATION
--------------
[ ] PASS - Ready for production deployment
[ ] PASS WITH WARNINGS - Deploy with known issues documented
[ ] FAIL - Critical issues must be fixed before deployment
```

---

## Next Steps After Testing

### If All Tests Pass
1. Generate final test report
2. Document performance baselines
3. Proceed with user deployment
4. Set up monitoring

### If Tests Fail
1. Document failures with reproduction steps
2. Prioritize fixes by severity
3. Fix critical (P0) issues
4. Re-run failed tests
5. Full regression test if major changes made

---

## Test Automation

All tests can be automated using the provided test scripts:

```bash
# Run all tests
npm run test:functional

# Run specific category
npm run test:functional -- --grep "Database Connectivity"

# Run with coverage
npm run test:functional:coverage

# Generate report
npm run test:report
```

---

**Version:** 1.0.0
**Last Updated:** 2025-01-14
