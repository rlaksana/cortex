# Wave-A Task Agent Selection

## Analysis Summary
Based on the remaining 22 tasks from the 30-task checklist, selected 5 Task Agents for parallel Wave-A execution following priority order: tests → types → integration → services → component → styles → pkg/docs.

## Wave-A Task Agent Selection (5 Agents, 10 tasks total)

### Agent 1: Test Coverage & Quality Agent (2 tasks)
**Priority:** HIGH (tests/TDD category)
**Tasks:**
- T09: Coverage HTML artifact (≥85% global; ≥90% critical paths) [ACTIVE TASK]
- T22: API contract tests (tool I/O)

**Rationale:** Highest priority category, ensures test infrastructure and API validation foundations.

### Agent 2: Type System & Validation Agent (1 task)  
**Priority:** HIGH (types/DTOs category)
**Tasks:**
- T20: Stabilize knowledge type validators

**Rationale:** High priority types category, foundational for type safety across the system.

### Agent 3: Integration & Architecture Agent (2 tasks)
**Priority:** HIGH (integration/routes/imports/exports/DI/policies category)
**Tasks:**
- T14: Dependency Injection shim
- T15: Remove tight coupling hot spots

**Rationale:** High priority integration tasks, critical for architecture improvements and code maintainability.

### Agent 4: Services & Performance Agent (3 tasks)
**Priority:** MEDIUM-HIGH (services/hooks/utils category)
**Tasks:**
- T12: Performance smoke + baseline  
- T18: Security runtime checks
- T26: Pin HTTP timeouts & retries in config

**Rationale:** Medium-high priority services that improve reliability, performance, and security.

### Agent 5: Core Component Cleanup Agent (2 tasks)
**Priority:** MEDIUM (component/core category)
**Tasks:**
- T17: Prune obsolete PostgreSQL references
- T29: Remove @ts-ignore/eslint-disable debt

**Rationale:** Component cleanup tasks that improve code quality and remove technical debt.

## Wave-B Pending Tasks (12 tasks)
**Categories:** pkg/docs/config (8 tasks), remaining services (4 tasks)
**Tasks:** T10, T11, T13, T16, T19, T21, T23, T24, T25, T27, T28, T30

## Selection Strategy
1. **Active task continuation:** T09 maintains momentum
2. **Priority alignment:** Focus on tests, types, integration categories
3. **Parallel execution:** Agents can work independently
4. **Foundation building:** Early improvements enable subsequent tasks
5. **Impact optimization:** High-value, medium-effort tasks prioritized

**Total Wave-A Coverage:** 45% of remaining tasks (10/22)
**Estimated Wave-A Duration:** 2-4 hours depending on agent velocity