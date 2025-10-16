# Tasks: Cortex Memory MCP v1

**Input**: Design documents from `/specs/001-create-specs-000/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: This feature explicitly requests TDD approach - all phases include RED→GREEN→refactor cycles.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`
- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3, US4)
- Include exact file paths in descriptions

## Path Conventions
- Single MCP server project: `src/`, `tests/` at repository root
- Migrations: `migrations/` directory
- Contracts: Pre-generated in `specs/001-create-specs-000/contracts/`

---

## Phase 1: Setup (Shared Infrastructure) - Slice 0

**Purpose**: Project initialization, build tools, CI pipeline

- [x] T001 Create project structure: `package.json`, `tsconfig.json`, `src/`, `tests/`, `migrations/`, `.env.example`
- [x] T002 Initialize TypeScript project with dependencies: `@modelcontextprotocol/sdk@1.0+`, `zod@3.22+`, `pg@8.11+`, `pino@8.16+`, `drizzle-kit@0.20+`, `vitest@1.0+`, `@testcontainers/postgresql@10+`, `k6@0.48+`
- [x] T003 [P] Configure ESLint + Prettier in `eslint.config.js`, `.prettierrc.js`
- [x] T004 [P] Setup Vitest config in `vitest.config.ts` (unit + integration test modes)
- [x] T005 [P] Create CI workflow in `.github/workflows/ci.yml` (lint, typecheck, test, build)
- [x] T006 Create npm scripts in `package.json`: `dev`, `build`, `test`, `test:integration`, `test:e2e`, `lint`, `typecheck`, `db:generate`, `db:migrate`, `db:seed`
- [x] T007 [P] Create base logger in `src/utils/logger.ts` using Pino with structured JSON output
- [x] T008 [P] Create environment config loader in `src/config/env.ts` using `zod` to validate `DATABASE_URL`, `LOG_LEVEL`, `NODE_ENV`

**Exit Criteria**: `npm run test` executes empty test suite successfully; CI pipeline passes on empty repo

---

## Phase 2: Foundational (Blocking Prerequisites) - Slice 1

**Purpose**: Database schema, extensions, migrations, core infrastructure that MUST complete before ANY user story

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

### Tests for Foundational Phase (RED first) ⚠️

- [ ] T009 [P] [FOUND] Migration smoke test in `tests/integration/db/migrations.test.ts`: verify migrations apply cleanly, extensions exist (pgcrypto, pg_trgm)
- [ ] T010 [P] [FOUND] Schema validation test in `tests/integration/db/schema.test.ts`: verify all 11 tables exist with correct columns, indexes (GIN for FTS, tags), triggers (t_*_touch, t_audit_*, t_adr_immutable, t_doc_approved_lock)
- [ ] T011 [P] [FOUND] Seed data test in `tests/integration/db/seed.test.ts`: verify seed script inserts 1 document, 3 sections, 1 ADR, 1 issue, 1 todo

### Implementation for Foundational Phase (GREEN)

- [x] T012 [FOUND] Create Drizzle schema definitions in `src/db/schema.ts`: define all 11 tables (document, section, runbook, pr_context, ddl_history, release_note, change_log, issue_log, adr_decision, todo_log, event_audit) with uuidv7() defaults, JSONB tags, generated columns (body_text, ts tsvector)
- [x] T013 [FOUND] Generate migration `migrations/0001_initial_schema.sql`: CREATE EXTENSION pgcrypto, pg_trgm; CREATE TABLE for all 11 tables per data-model.md DDL
- [x] T014 [FOUND] Generate migration `migrations/0002_indexes.sql`: CREATE INDEX for GIN (section.ts, section.tags, section.body_jsonb, runbook.tags, change_log.tags, issue_log.tags, adr_decision.tags, todo_log.tags); CREATE INDEX on event_audit (entity_type, entity_id, created_at)
- [x] T015 [FOUND] Generate migration `migrations/0003_triggers.sql`: CREATE TRIGGER for auto-updated_at (t_document_touch, t_section_touch, t_runbook_touch, t_change_touch, t_issue_touch, t_adr_touch, t_todo_touch), audit logging (t_audit_*), immutability (t_adr_immutable for status='accepted', t_doc_approved_lock for approved_at IS NOT NULL)
- [x] T016 [FOUND] Implement migration runner in `src/db/migrate.ts`: read migrations from `migrations/`, apply in order, record in `ddl_history` table
- [x] T017 [FOUND] Create seed data script in `scripts/seed.ts`: insert 1 document (title="Getting Started Guide", type="guide"), 3 sections (chunked, with FTS vectors), 1 ADR (status="accepted"), 1 issue (status="open"), 1 todo (status="open") with scope `{project: "cortex-memory", branch: "main"}`
- [x] T018 [FOUND] Create database connection pool in `src/db/pool.ts`: use `pg.Pool` with config from env (min=2, max=10, idleTimeout=30s), export singleton instance
- [x] T019 [P] [FOUND] Create scope inference utility in `src/utils/scope.ts`: read env vars (CORTEX_ORG, CORTEX_PROJECT, CORTEX_BRANCH) with fallback to git commands (`git config remote.origin.url`, `git rev-parse --abbrev-ref HEAD`), cache result per session
- [x] T020 [P] [FOUND] Create content hash utility in `src/utils/hash.ts`: normalize text (trim, collapse whitespace, lowercase), compute SHA-256 using Node.js crypto module

### Refactor Foundational Phase

- [x] T021 [FOUND] Validate all migrations run successfully via `npm run db:migrate`
- [ ] T022 [FOUND] Confirm all tests pass: `npm run test:integration -- tests/integration/db/`
- [ ] T023 [FOUND] Setup Testcontainers base config in `tests/helpers/testcontainers.ts`: PostgreSQL 18-alpine, auto-install extensions, run migrations, seed fixtures

**Checkpoint**: Foundation ready - database schema live, migrations verified, scope inference working, test infrastructure operational

---

## Phase 3: User Story 1 - Store and Retrieve Cross-Session Knowledge (Priority: P1) 🎯 MVP

**Goal**: Implement `memory.store` and `memory.find` for **section** knowledge type only, with idempotency, deduplication, FTS search, and cross-type search foundation

**Independent Test**: Store sections via `memory.store`, retrieve via `memory.find` with different queries, verify dedupe behavior with idempotency keys

### Tests for User Story 1 - Part A: memory.store (RED first) ⚠️

- [x] T024 [P] [US1] Contract test for `memory.store` in `tests/contract/memory-store.test.ts`: validate input schema (valid section with all required fields passes, missing title/body fails with INVALID_SCHEMA error code)
- [ ] T025 [P] [US1] Idempotency test in `tests/integration/memory-store-idempotency.test.ts`: store same section twice with same idempotency_key → second returns status="skipped_dedupe", verify only 1 row in section table
- [ ] T026 [P] [US1] Content deduplication test in `tests/integration/memory-store-dedupe.test.ts`: store section without idempotency_key, compute content_hash → store identical content again → second returns "skipped_dedupe"
- [ ] T027 [P] [US1] Audit trail test in `tests/integration/memory-store-audit.test.ts`: store section → verify event_audit row created with entity_type='section', operation='INSERT', actor/timestamp populated

### Implementation for User Story 1 - Part A: memory.store (GREEN)

- [x] T028 [US1] Copy Zod schemas from `specs/001-create-specs-000/contracts/knowledge-types.ts` to `src/schemas/knowledge-types.ts`: SectionSchema, ScopeSchema, SourceSchema, validateKnowledgeItem, safeValidateKnowledgeItem
- [x] T029 [US1] Implement `memory.store` service in `src/services/memory-store.ts`:
  - Validate input items using Zod (safeValidateKnowledgeItem)
  - For each item: compute content_hash if missing (use src/utils/hash.ts), check for existing content_hash in section table
  - If exists → return status="skipped_dedupe", if not exists → INSERT with uuidv7() id
  - Return {stored: [{id, status, kind, created_at}], errors: [{index, error_code, message, field}]}
- [x] T030 [US1] Create audit logging helper in `src/db/audit.ts`: insert row into event_audit table with entity_type, entity_id, operation, actor (from source.actor), timestamp, change_summary JSONB
- [x] T031 [US1] Integrate audit logging into memory-store.ts: after successful INSERT/UPDATE, call audit helper with operation='INSERT' or 'UPDATE'

### Tests for User Story 1 - Part B: memory.find (RED first) ⚠️

- [x] T032 [P] [US1] FTS search test in `tests/integration/memory-find-fts.test.ts`: seed 10 sections with keywords ("authentication", "JWT", "OAuth"), query "JWT tokens" → verify hits include sections with those keywords, score > 0, snippet highlighted
- [ ] T033 [P] [US1] Empty results test in `tests/integration/memory-find-empty.test.ts`: query with no matches → return {hits: [], suggestions: []} with no errors
- [ ] T034 [P] [US1] Top-k limit test in `tests/integration/memory-find-topk.test.ts`: seed 20 sections, query with top_k=5 → verify exactly 5 hits returned, ordered by score descending
- [ ] T035 [P] [US1] Latency test in `tests/integration/memory-find-perf.test.ts`: seed 1000 sections, measure query duration → verify P95 < 300ms (use 10 sample queries)

### Implementation for User Story 1 - Part B: memory.find (GREEN)

- [x] T036 [US1] Implement `memory.find` service in `src/services/memory-find.ts`:
  - Parse query string into FTS query using to_tsquery
  - Build SQL: SELECT id, heading, body_jsonb, ts_rank(ts, query) AS score FROM section WHERE ts @@ query ORDER BY score DESC LIMIT top_k
  - For each hit: extract snippet using ts_headline, return {kind: "section", id, title: heading, snippet, score}
  - Return {hits: [], suggestions: [], debug: {query_duration_ms, total_candidates, filters_applied}}
- [x] T037 [US1] Implement snippet generation in `src/utils/snippet.ts`: use ts_headline(body_text, query, 'MaxWords=30, MinWords=15') to extract highlighted excerpt
- [x] T038 [US1] Implement performance instrumentation in memory-find.ts: measure query duration using pino child logger, log query_duration_ms, warn if > 200ms

### Tests for User Story 1 - Part C: All 9 Kinds (RED first) ⚠️

- [ ] T039 [P] [US1] Multi-type schema validation test in `tests/contract/knowledge-types.test.ts`: validate all 9 types (section, runbook, change, issue, decision, todo, release_note, ddl, pr_context) with minimal required fields → all pass, test missing required fields → all fail with specific error messages
- [ ] T040 [P] [US1] Runbook storage test in `tests/integration/memory-store-runbook.test.ts`: store runbook with service="auth-api", steps=[{step_number:1, description:"Restart service"}] → verify inserted, content chunked if steps exceed 3KB
- [ ] T041 [P] [US1] Cross-type search test in `tests/integration/memory-find-cross-type.test.ts`: seed 2 sections, 1 ADR, 1 issue all with keyword "authentication" → query without type filter → verify hits include all 3 types ranked by relevance

### Implementation for User Story 1 - Part C: All 9 Kinds (GREEN)

- [x] T042 [P] [US1] Implement service layer for runbook in `src/services/knowledge/runbook.ts`: store runbook to runbook table, chunk steps_jsonb if exceeds 3KB (split into multiple runbooks with tags.part=1,2,3)
- [x] T043 [P] [US1] Implement service layer for change in `src/services/knowledge/change.ts`: store to change_log table, dedupe via content_hash on summary field
- [x] T044 [P] [US1] Implement service layer for issue in `src/services/knowledge/issue.ts`: store to issue_log table, dedupe via composite key (tracker + external_id)
- [x] T045 [P] [US1] Implement service layer for decision (ADR) in `src/services/knowledge/decision.ts`: store to adr_decision table, enforce immutability check before UPDATE (violatesADRImmutability helper)
- [x] T046 [P] [US1] Implement service layer for todo in `src/services/knowledge/todo.ts`: store to todo_log table, apply TTL policy (default: archive after 90d when status=done/cancelled)
- [x] T047 [P] [US1] Implement service layer for release_note in `src/services/knowledge/release_note.ts`: store to release_note table
- [x] T048 [P] [US1] Implement service layer for ddl in `src/services/knowledge/ddl.ts`: store to ddl_history table, enforce checksum validation
- [x] T049 [P] [US1] Implement service layer for pr_context in `src/services/knowledge/pr_context.ts`: store to pr_context table with expires_at = merged_at + 30d (TTL policy)
- [x] T050 [US1] Refactor memory-store.ts to route by kind: use discriminated union switch (if kind === 'section' → section service, else if kind === 'runbook' → runbook service, etc.)
- [x] T051 [US1] Extend memory-find.ts to search across all types: UNION query (SELECT FROM section UNION ALL SELECT FROM runbook UNION ALL SELECT FROM change_log...), rank by combined FTS score

### Refactor User Story 1

- [ ] T052 [US1] Extract common storage patterns into `src/services/knowledge/base.ts`: deduplication logic, audit logging wrapper, error normalization
- [ ] T053 [US1] Add integration test suite coverage report: ensure all 9 kinds have store + find + dedupe tests
- [ ] T054 [US1] Validate quickstart.md examples work: run example `memory.store` and `memory.find` calls from quickstart.md, verify responses match documented schemas

**Checkpoint**: User Story 1 complete - can store and retrieve all 9 knowledge types with deduplication, audit trail, and FTS search

---

## Phase 4: User Story 2 - Branch-Isolated Context Retrieval (Priority: P2)

**Goal**: Implement default branch isolation for `memory.find`, explicit scope widening, and scope proximity ranking

**Independent Test**: Store items in different branch scopes, verify default searches return only current branch, confirm scope widening works

### Tests for User Story 2 (RED first) ⚠️

- [ ] T055 [P] [US2] Branch isolation test in `tests/integration/memory-find-branch-isolation.test.ts`: seed 3 sections (branch="main"), 2 sections (branch="feature-A") → query from branch="main" context (no explicit scope) → verify only 3 main-branch sections returned
- [ ] T056 [P] [US2] Explicit scope widening test in `tests/integration/memory-find-scope-widen.test.ts`: query with scope={project: "cortex-memory"} (no branch specified) → verify results include sections from all branches, ranked by scope proximity
- [ ] T057 [P] [US2] Scope proximity ranking test in `tests/integration/memory-find-scope-rank.test.ts`: seed sections with scope combinations (exact branch match, same project different branch, cross-project) → verify exact branch match scores highest (proximity=1.0), same project scores 0.5, cross-project scores 0.2

### Implementation for User Story 2 (GREEN)

- [x] T058 [US2] Implement scope filter builder in `src/services/filters/scope-filter.ts`:
  - If no scope provided in query → infer from environment (src/utils/scope.ts) → default to {project, branch}
  - If partial scope provided → build WHERE clause: `tags @> '{"project": "cortex-memory"}'::jsonb AND tags @> '{"branch": "main"}'::jsonb`
  - Return SQL filter string and scope_proximity factor for ranking
- [x] T059 [US2] Integrate scope filtering into memory-find.ts: apply scope filter to WHERE clause before FTS query
- [x] T060 [US2] Implement scope proximity scoring in `src/services/ranking/scope-proximity.ts`:
  - Exact match all levels (org, project, branch) → 1.0
  - Match project + service but different branch → 0.5
  - Match project only → 0.3
  - Cross-project → 0.2
  - Return proximity score per hit
- [x] T061 [US2] Integrate scope proximity into final ranking formula in memory-find.ts: `final_score = (0.4 × fts_score) + (0.3 × recency_boost) + (0.2 × scope_proximity) + (0.1 × citation_count)` (per research.md Decision 5)

### Refactor User Story 2

- [ ] T062 [US2] Add scope validation: reject invalid scope combinations (e.g., tenant without org) with error_code="INVALID_SCOPE", human-readable hint
- [ ] T063 [US2] Add debug logging for scope inference: log inferred scope (org, project, branch) at INFO level, include in response.debug.filters_applied

**Checkpoint**: User Story 2 complete - branch isolation working, scope widening functional, scope proximity ranking integrated

---

## Phase 5: User Story 3 - Comprehensive Audit and Immutability (Priority: P3)

**Goal**: Enforce ADR content immutability (status='accepted'), approved spec write-lock, 100% audit coverage verification

**Independent Test**: Attempt to modify immutable content, verify rejections; query audit log, confirm 100% mutation coverage

### Tests for User Story 3 (RED first) ⚠️

- [x] T064 [P] [US3] ADR immutability test in `tests/integration/immutability-adr.test.ts`: store ADR with status="accepted" → attempt UPDATE to change rationale → verify rejected with error_code="IMMUTABILITY_VIOLATION"
- [ ] T065 [P] [US3] Approved spec write-lock test in `tests/integration/immutability-spec.test.ts`: store document with approved_at=now() → attempt UPDATE to body_text → verify trigger blocks change, returns error_code="WRITE_LOCK_VIOLATION"
- [ ] T066 [P] [US3] Audit coverage test in `tests/integration/audit-coverage.test.ts`: perform 10 mutations (INSERT section, UPDATE runbook, DELETE issue) → query event_audit → verify 10 audit entries exist with correct entity_type, operation, timestamps
- [ ] T067 [P] [US3] Audit append-only test in `tests/integration/audit-append-only.test.ts`: attempt UPDATE/DELETE on event_audit table → verify database rejects (no UPDATE/DELETE permissions on event_audit for app role)

### Implementation for User Story 3 (GREEN)

- [x] T068 [US3] Implement ADR immutability check in decision.ts service: before UPDATE, fetch existing ADR → if status='accepted', call violatesADRImmutability helper (from knowledge-types.ts) → if violated, return error without executing UPDATE
- [x] T069 [US3] Implement approved spec write-lock check in `src/utils/immutability.ts`: before UPDATE, check if parent document has approved_at IS NOT NULL → if yes, call violatesSpecWriteLock helper → reject with WRITE_LOCK_VIOLATION
- [x] T070 [US3] Create database migration `migrations/0004_audit_permissions.sql`: REVOKE UPDATE, DELETE ON event_audit FROM cortex_app_role; GRANT INSERT, SELECT ON event_audit TO cortex_app_role (enforce append-only at DB level)
- [x] T071 [US3] Implement audit query utility in `src/services/audit/query.ts`: expose queryAuditLog(filters: {entity_type?, entity_id?, since?, until?}) → return audit entries with pagination
- [x] T072 [US3] Create audit coverage verification script in `scripts/verify-audit-coverage.ts`: query all tables for row count, compare to event_audit distinct entity_id count → report coverage percentage, fail if < 100%

### Refactor User Story 3

- [ ] T073 [US3] Add immutability violation error messages to all knowledge services: standardize error_code and human_hint format
- [ ] T074 [US3] Document immutability rules in `docs/immutability.md`: explain ADR accepted status lock, approved spec lock, audit append-only policy

**Checkpoint**: User Story 3 complete - immutability enforced, audit trail verified, governance policies active

---

## Phase 6: User Story 4 - Intelligent Search with Routing and Suggestions (Priority: P3)

**Goal**: Implement mode-based routing (auto/fast/deep), search suggestions on low recall, confidence scoring, route reporting

**Independent Test**: Submit queries with different modes, verify appropriate routes selected, measure latency differences, confirm suggestions appear for low-recall queries

### Tests for User Story 4 (RED first) ⚠️

- [ ] T075 [P] [US4] Mode routing test in `tests/integration/memory-find-mode-routing.test.ts`: query with mode="fast" → verify route_used="fts", P95 < 100ms; query with mode="deep" → verify route_used includes "trigram" or "semantic", P95 < 300ms
- [ ] T076 [P] [US4] Low-recall suggestions test in `tests/integration/memory-find-suggestions.test.ts`: query with no matches (e.g., "xyzabc123") → verify response.suggestions includes ["Try broader terms", "Check spelling", "Remove filters"]
- [ ] T077 [P] [US4] Confidence scoring test in `tests/integration/memory-find-confidence.test.ts`: query with exact match (e.g., issue external_id) → verify confidence ≥ 0.9; query with fuzzy match → verify confidence between 0.5-0.8
- [ ] T078 [P] [US4] Auto mode routing test in `tests/integration/memory-find-mode-auto.test.ts`: query containing "GH-123" pattern (issue ID) → verify auto mode routes to logs-first strategy, route_used="logs_fts"

### Implementation for User Story 4 (GREEN)

- [x] T079 [US4] Implement mode router in `src/services/routing/mode-router.ts`:
  - If mode="fast" → return strategy="fts_only"
  - If mode="deep" → return strategy="fts_plus_trigram"
  - If mode="auto" → analyze query for patterns (issue IDs, PR numbers, commit SHAs) → route to logs-first if detected, else default to fts_only
  - Return {strategy, confidence}
- [x] T080 [US4] Implement deep search with pg_trgm in `src/services/search/deep-search.ts`: extend FTS query with similarity(body_text, query) > 0.3 using pg_trgm, combine scores: `0.7 × fts_score + 0.3 × similarity_score`
- [x] T081 [US4] Implement suggestion generator in `src/services/search/suggestions.ts`: if hits.length < 3, generate suggestions based on query analysis (check for typos using pg_trgm, suggest removing filters, recommend broader terms)
- [x] T082 [US4] Implement confidence calculator in `src/services/ranking/confidence.ts`:
  - Exact match (e.g., external_id lookup) → 0.95
  - High FTS rank (ts_rank > 0.5) → 0.85
  - Fuzzy match (trigram similarity 0.3-0.6) → 0.6
  - Low recall → 0.3
  - Return confidence per query
- [x] T083 [US4] Integrate routing into memory-find.ts: call mode-router to get strategy, execute appropriate search (fts_only vs fts_plus_trigram), add route_used and confidence to response

### Refactor User Story 4

- [x] T084 [US4] Implement final ranking formula in `src/services/ranking/ranker.ts`: consolidate all scoring components (fts_score, recency_boost, scope_proximity, citation_count) using formula from research.md Decision 5: `final_score = (0.4 × fts_score) + (0.3 × recency_boost) + (0.2 × scope_proximity) + (0.1 × citation_count)`
- [x] T085 [US4] Add recency boost calculator in `src/services/ranking/recency.ts`: `recency_boost = 1.0 - (log10(1 + days_since_update) / log10(180))` (1.0 @ 7d → 0.1 @ 180d per research.md Decision 5)
- [x] T086 [US4] Add citation count normalization in `src/services/ranking/citation.ts`: `citation_score = min(1.0, log10(1 + citation_count) / 2)` (logarithmic scaling per research.md Decision 5)

**Checkpoint**: User Story 4 complete - intelligent routing functional, suggestions generated, confidence scoring accurate, ranking formula implemented

---

## Phase 7: E2E MCP Integration (STDIO) - Slice 7

**Purpose**: Wire up MCP protocol, STDIO transport, golden path testing

### Tests for E2E Integration (RED first) ⚠️

- [x] T087 [P] [E2E] MCP STDIO transport test in `tests/e2e/mcp-stdio.test.ts`: spawn server process with STDIO, send JSON-RPC request for tools/list → verify response includes memory.find and memory.store
- [x] T088 [P] [E2E] Golden path test in `tests/e2e/golden-store-find.test.ts`: send memory.store request (section), then memory.find request (query for stored content) → verify full round-trip works, response matches schema
- [ ] T089 [P] [E2E] Schema conformance test in `tests/e2e/schema-conformance.test.ts`: validate all responses against JSON schemas from `contracts/mcp-tools.json`, ensure no extra fields, all required fields present
- [ ] T090 [P] [E2E] Error handling test in `tests/e2e/mcp-errors.test.ts`: send invalid memory.store request (missing required field) → verify JSON-RPC error response with error_code and human_hint

### Implementation for E2E Integration (GREEN)

- [x] T091 [E2E] Create MCP server entrypoint in `src/index.ts`: initialize MCP SDK with STDIO transport, register memory.find and memory.store tools
- [x] T092 [E2E] Implement memory.find MCP tool wrapper in `src/mcp/tools/memory-find.ts`: validate input using Zod, call memory-find.ts service, format response per mcp-tools.json output schema
- [x] T093 [E2E] Implement memory.store MCP tool wrapper in `src/mcp/tools/memory-store.ts`: validate input using Zod, call memory-store.ts service, format response per mcp-tools.json output schema
- [x] T094 [E2E] Create MCP manifest in `mcp.json`: define tool schemas (copy from contracts/mcp-tools.json), set name="cortex-memory", version="1.0.0", transport="stdio"
- [x] T095 [E2E] Implement graceful shutdown in src/index.ts: handle SIGINT/SIGTERM, close database pool, flush logs

### Refactor E2E Integration

- [ ] T096 [E2E] Add request/response logging: log all MCP requests at INFO level with request_id (UUID v7), include tool_name, sql_duration_ms, result_count in response log
- [ ] T097 [E2E] Validate against quickstart.md examples: run all example JSON-RPC calls from quickstart.md, verify responses match documented output

**Checkpoint**: E2E integration complete - MCP server functional over STDIO, tools registered, golden tests passing

---

## Phase 8: Performance & Polish - Slice 8

**Purpose**: k6 load testing, performance validation, documentation, release preparation

### Tests for Performance & Polish (RED first) ⚠️

- [ ] T098 [P] [PERF] k6 load test in `tests/perf/load-test.js`: generate 100K sections using Faker.js (per research.md Decision 9), run 500 queries → verify P95 latency < 300ms, throughput > 50 QPS
- [ ] T099 [P] [PERF] Relevance evaluation test in `tests/perf/relevance-eval.ts`: sample 30 queries with known-good results, measure Top-3 precision → verify ≥ 80% relevance (per FR-051)
- [ ] T100 [P] [PERF] Concurrent query test in `tests/perf/concurrent.js`: run 100 parallel memory.find requests → verify no degradation, P95 remains < 300ms

### Implementation for Performance & Polish (GREEN)

- [ ] T101 [P] [PERF] Create synthetic dataset generator in `scripts/perf/generate-dataset.ts`: use Faker.js to generate 100K sections, 15K changes, 10K issues, 5K ADRs/runbooks with realistic scope distribution (4 projects × 4 branches per research.md Decision 9)
- [ ] T102 [P] [PERF] Create k6 load test script in `tests/perf/load-test.js`: ramp up from 10 to 100 VUs over 2 minutes, maintain 100 VUs for 5 minutes, measure http_req_duration P95, verify < 300ms threshold
- [ ] T103 [P] [PERF] Create relevance evaluation script in `scripts/perf/relevance-eval.ts`: define 30 golden queries with expected Top-3 results, run against seeded database, calculate precision, log results
- [ ] T104 [PERF] Document setup in `README.md`: installation steps, prerequisites (Docker, Node.js 20+), quickstart reference, link to spec.md and plan.md
- [ ] T105 [PERF] Create release notes in `RELEASE_NOTES.md`: summarize v1.0.0 features (2 tools, 9 knowledge types, branch isolation, audit trail, FTS search, P95 < 300ms SLO), known limitations (no semantic search, single-instance only)
- [ ] T106 [PERF] Create TTL cleanup cron script in `scripts/ttl-cleanup.sh`: DELETE FROM pr_context WHERE expires_at < now(); UPDATE todo_log SET status='archived' WHERE closed_at < now() - interval '90 days'; VACUUM ANALYZE (per research.md Decision 6)

### Refactor Performance & Polish

- [ ] T107 [PERF] Add slow query logging: configure Pino to WARN when query_duration_ms > 200ms, include query text and filters in log
- [ ] T108 [PERF] Create performance evidence report in `docs/performance-evidence.md`: include k6 output, P95 latency metrics, relevance evaluation results, throughput data
- [ ] T109 [PERF] Validate all constitution principles: run comprehensive test suite, confirm all 7 principles from constitution.md are satisfied (Minimal API, Single SoT, Branch Isolation, Immutability, Extensibility, Performance SLOs, Type Safety)

**Exit Criteria**: P95 < 300ms on 100K-1M sections verified, Top-3 ≥ 80% relevance achieved, all SLOs met, documentation complete, release notes published

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Story 1 (Phase 3)**: Depends on Foundational (Phase 2) - No dependencies on other stories
- **User Story 2 (Phase 4)**: Depends on User Story 1 (requires memory.find to exist) - Can partially overlap with US1 Part C
- **User Story 3 (Phase 5)**: Depends on User Story 1 (requires memory.store services) - Can work in parallel with US2
- **User Story 4 (Phase 6)**: Depends on User Story 1 + 2 (requires memory.find with scope filtering) - Can work in parallel with US3
- **E2E Integration (Phase 7)**: Depends on all user stories being complete
- **Performance & Polish (Phase 8)**: Depends on E2E Integration completion

### User Story Dependencies

- **User Story 1 (P1)**: FOUNDATIONAL - all other stories depend on this
- **User Story 2 (P2)**: Extends User Story 1 (adds scope filtering to memory.find)
- **User Story 3 (P3)**: Extends User Story 1 (adds immutability to memory.store services)
- **User Story 4 (P3)**: Extends User Story 1 + 2 (adds intelligent routing to memory.find)

### Within Each User Story (TDD Order)

1. **RED**: Write tests FIRST, ensure they FAIL
2. **GREEN**: Implement minimum code to make tests pass
3. **REFACTOR**: Clean up, extract helpers, optimize
4. Models/schemas before services
5. Services before MCP tool wrappers
6. Core implementation before extensions

### Parallel Opportunities

- **Phase 1 (Setup)**: T003 (ESLint), T004 (Vitest), T005 (CI), T007 (logger), T008 (env config) can run in parallel
- **Phase 2 (Foundational)**: T009, T010, T011 (tests) can run in parallel; T019 (scope inference), T020 (hash utility) can run in parallel
- **Phase 3 (US1)**: Within each part (A, B, C), all tests marked [P] can run in parallel; within Part C, T042-T049 (knowledge services) can run in parallel
- **Phase 4 (US2)**: T055, T056, T057 (tests) can run in parallel
- **Phase 5 (US3)**: T064, T065, T066, T067 (tests) can run in parallel
- **Phase 6 (US4)**: T075, T076, T077, T078 (tests) can run in parallel
- **Phase 7 (E2E)**: T087, T088, T089, T090 (tests) can run in parallel
- **Phase 8 (Perf)**: T098, T099, T100 (tests) can run in parallel; T101, T102, T103 (perf scripts) can run in parallel

---

## Parallel Example: User Story 1 Part A

```bash
# Launch all tests for memory.store together (RED phase):
Task: "Contract test for memory.store in tests/contract/memory-store.test.ts"
Task: "Idempotency test in tests/integration/memory-store-idempotency.test.ts"
Task: "Content deduplication test in tests/integration/memory-store-dedupe.test.ts"
Task: "Audit trail test in tests/integration/memory-store-audit.test.ts"

# Implement service layer (GREEN phase):
Task: "Copy Zod schemas to src/schemas/knowledge-types.ts"
Task: "Implement memory.store service in src/services/memory-store.ts"
Task: "Create audit logging helper in src/db/audit.ts"
Task: "Integrate audit logging into memory-store.ts"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only - Slice 2, 3, 4)

1. Complete Phase 1: Setup (Slice 0)
2. Complete Phase 2: Foundational (Slice 1) - CRITICAL BLOCKING PHASE
3. Complete Phase 3: User Story 1 Part A (memory.store for sections)
4. Complete Phase 3: User Story 1 Part B (memory.find for sections)
5. Complete Phase 3: User Story 1 Part C (all 9 knowledge types)
6. **STOP and VALIDATE**: Test User Story 1 independently - can store and retrieve all 9 types
7. Deploy/demo if ready - this is a functional MVP

### Incremental Delivery (Recommended)

1. **Foundation**: Complete Setup + Foundational → Database ready, test infrastructure operational
2. **MVP (US1)**: Add User Story 1 → Test independently → **DELIVERABLE: Core store/find functionality**
3. **Branch Isolation (US2)**: Add User Story 2 → Test independently → **DELIVERABLE: Multi-branch support**
4. **Governance (US3)**: Add User Story 3 → Test independently → **DELIVERABLE: Production-ready audit/immutability**
5. **Intelligence (US4)**: Add User Story 4 → Test independently → **DELIVERABLE: Enhanced search UX**
6. **Integration (E2E)**: Complete E2E phase → **DELIVERABLE: Full MCP server over STDIO**
7. **Performance (Perf)**: Validate SLOs → **DELIVERABLE: v1.0.0 release candidate**

### Parallel Team Strategy

With multiple developers:

1. **Week 1**: Team completes Setup + Foundational together (T001-T023)
2. **Week 2-3**: Once Foundational is done, split into parallel tracks:
   - Developer A: User Story 1 Part A + B (memory.store + memory.find for sections)
   - Developer B: User Story 1 Part C (extend to 9 knowledge types)
   - Developer C: Foundational test coverage + documentation
3. **Week 4**: Integrate User Story 1, validate MVP
4. **Week 5**: Parallel again:
   - Developer A: User Story 2 (branch isolation)
   - Developer B: User Story 3 (audit/immutability)
   - Developer C: User Story 4 (routing/suggestions)
5. **Week 6**: E2E integration + performance validation
6. Stories complete and integrate independently, MVP can ship at any checkpoint

---

## Notes

- **[P] tasks** = different files, no dependencies between them - safe to parallelize
- **[Story] label** maps each task to specific user story (US1, US2, US3, US4) for traceability
- **TDD Workflow**: RED (write failing test) → GREEN (implement to pass) → REFACTOR (clean up)
- **Each user story** should be independently completable and testable - can ship US1 without US2/US3/US4
- **Verify tests fail** before implementing (RED phase validation)
- **Commit after each task** or logical group (e.g., after completing all US1 Part A tests)
- **Stop at any checkpoint** to validate story independently - deliver incrementally
- **Avoid**: vague tasks, same file conflicts, cross-story dependencies that break independence
- **Constitutional alignment**: All tasks mapped to constitution principles - validate after Phase 8 completion

---

## Total Task Count

- **Setup**: 8 tasks (T001-T008)
- **Foundational**: 15 tasks (T009-T023)
- **User Story 1**: 31 tasks (T024-T054)
- **User Story 2**: 8 tasks (T055-T063)
- **User Story 3**: 11 tasks (T064-T074)
- **User Story 4**: 12 tasks (T075-T086)
- **E2E Integration**: 7 tasks (T087-T097)
- **Performance & Polish**: 12 tasks (T098-T109)
- **TOTAL**: **109 tasks**

**Parallel opportunities**: 45 tasks marked [P] (41% can run in parallel)

**Suggested MVP scope**: Phases 1, 2, 3 (User Story 1 only) = **54 tasks** → delivers core store/find for all 9 knowledge types
