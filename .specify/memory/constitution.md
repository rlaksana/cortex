<!--
Sync Impact Report:
- Version change: 1.0.0 (initial ratification)
- Ratification date: 2025-10-09
- Modified principles: N/A (initial creation)
- Added sections: All (Core Principles 1-7, Knowledge Architecture, Technology Stack, Development Workflow, Governance)
- Removed sections: N/A
- Templates requiring updates:
  ✅ plan-template.md (Constitution Check section verified compatible)
  ✅ spec-template.md (User Stories and Requirements align with TDD workflow)
  ✅ tasks-template.md (Phase structure aligns with vertical slices + TDD)
- Follow-up TODOs: None
-->

# Cortex Memory MCP Constitution

## Core Principles

### I. Minimal API Surface

**MUST** expose exactly two MCP tools: `memory.find` and `memory.store`. No additional tools permitted without constitutional amendment.

**Rationale**: Simplicity reduces cognitive load, testing surface, and maintenance burden. All functionality (chunking, deduplication, indexing, TTL, audit) handled server-side. Clients call two tools; server orchestrates complexity.

---

### II. Single Source of Truth (PostgreSQL 18+)

**MUST** use PostgreSQL 18+ as the exclusive source of truth for all persisted state. Vector databases (Qdrant) or graph databases (Neo4j) MAY be added as read-optimized indexes but MUST NOT become authoritative sources.

**Rationale**: Single SoT prevents data inconsistency, simplifies backup/recovery, and provides ACID guarantees. Postgres 18 delivers 3× I/O performance over 16, native `uuidv7()`, skip-scan optimization, and proven stability. Extension `pg_trgm` is REQUIRED for fuzzy search (`mode="deep"`).

---

### III. Branch Isolation by Default

**MUST** isolate reads to the caller's branch scope by default. Cross-branch queries require explicit client opt-in via scope widening.

**Rationale**: Prevents pollution of feature branch context with unrelated work. Mirrors git's working directory isolation. Enables parallel development without interference.

---

### IV. Immutable Content Integrity

**MUST** enforce immutability rules:
- **ADR content**: Once status is `accepted`, content becomes read-only (amendments create new ADR with `supersedes` link)
- **Event audit**: `event_audit` table is append-only; no updates or deletes permitted
- **Approved specs**: Write-lock when marked approved; changes require version bump + re-approval

**MUST** implement idempotent writes using `idempotency_key` or synthesized `{kind, scope, source, content_hash}` composite.

**Rationale**: Immutability enables reliable audit trails, safe concurrent operations, and cacheable reads. Idempotency prevents duplicate entries from retry storms.

---

### V. Extensibility Without API Breakage

**MUST** design for zero-API-change extensions. Future additions (vector search via Qdrant, graph traversal via Neo4j, ML-based reranking) MUST integrate server-side without altering `memory.find` or `memory.store` signatures.

**MUST** use `mode` parameter (`auto|fast|deep`) for routing strategy selection. Server interprets mode and evolves routing heuristics internally.

**Rationale**: Stable API contract protects client code from churn. Allows continuous performance improvements and feature additions without breaking changes.

---

### VI. Performance Discipline (Non-Negotiable SLOs)

**MUST** meet performance Service Level Objectives:
- **Latency**: `memory.find` P95 < 300ms on datasets ≤ 1–3M sections
- **Relevance**: Top-3 results ≥ 80% relevant (sampled evaluation)
- **Audit coverage**: 100% of mutations logged to `event_audit`

**MUST** measure P95 latency, relevance scores, and audit coverage in CI/CD gates. Regressions block merge.

**Rationale**: Cross-session memory is useless if slow or inaccurate. Audit completeness is non-negotiable for compliance and debugging. SLOs enforce quantitative accountability.

---

### VII. Type Safety & Schema Validation

**MUST** validate all inputs using strongly-typed schemas (TypeScript with Zod for TS implementation, Pydantic for Python).

**MUST** use discriminated unions for the 9 knowledge types (`section`, `runbook`, `change`, `issue`, `decision`, `todo`, `release_note`, `ddl`, `pr_context`) with type-specific required fields enforced at runtime and compile-time.

**Rationale**: Runtime validation catches malformed inputs before corruption. Compile-time types prevent entire classes of bugs. Discriminated unions enable exhaustive pattern matching and accurate IntelliSense.

---

## Knowledge Architecture

### Knowledge Types (9 Categories)

| Type | Purpose | Required Fields | TTL Policy |
|------|---------|----------------|------------|
| `section` | Documentation fragments | `title`, `body_md` OR `body_text` | `NONE` (perpetual) |
| `runbook` | Operational procedures | `service`, `steps[]` | `NONE` (verify every 90d) |
| `change` | Code/schema/config changes | `change_type`, `subject_ref`, `summary` | `BRANCH90d` |
| `issue` | Bug/feature tracker sync | `tracker`, `external_id`, `title`, `status` | `NONE` (until closed+90d) |
| `decision` | Architecture Decision Records | `component`, `status`, `title`, `rationale`, `alternatives[]` | `NONE` (immutable) |
| `todo` | Cross-session task tracking | `scope`, `todo_type`, `text` | `BRANCH90d` OR user-defined |
| `release_note` | Deployment/release artifacts | `version`, `highlights[]` | `NONE` |
| `ddl` | Database schema definitions | `entity`, `ddl_sql` | `NONE` |
| `pr_context` | Pull request analysis cache | `pr_id`, `repo`, `files[]`, `findings[]` | `PR30d` (expires 30d post-merge) |

### Scope Hierarchy

Six-level hierarchical scope for multi-tenant, multi-project isolation:
```
org → project → service → branch → sprint → tenant
```

Default read isolation: caller's `{org, project, branch}`. Server infers missing scope from git context when possible.

### Ranking Formula

```
final_score = (0.4 × fts_score) + (0.3 × recency_boost) + (0.2 × scope_proximity) + (0.1 × citation_count)
```

**Recency boost**: `1.0` if modified within 7d, decays to `0.1` after 180d (except immutable ADRs).
**Scope proximity**: `1.0` for exact branch match, `0.5` for same project/different branch, `0.2` for cross-project.
**Citation count**: Logarithmic scaling: `min(1.0, log10(1 + citation_count) / 2)`.

---

## Technology Stack

### Mandatory Components

- **Database**: PostgreSQL 18+ with extensions `pgcrypto`, `pg_trgm` (REQUIRED)
- **MCP Transport**: STDIO (JSON-RPC 2.0)
- **Schema Validation**: Zod (TypeScript) or Pydantic (Python)

### Recommended Implementation Stack

**Primary**: TypeScript (Node.js 20+)
- **Runtime**: Node.js 20+ with native `uuidv7()` polyfill (or `uuid` package)
- **DB Client**: `pg` (node-postgres) with connection pooling
- **MCP SDK**: `@modelcontextprotocol/sdk` (official Anthropic SDK)
- **Validation**: Zod 3.x (mirrors JSONB schemas in DDL)
- **Testing**: Vitest (unit), Supertest (integration), Testcontainers (E2E with real Postgres)

**Alternative**: Python 3.11+
- **Runtime**: Python 3.11+ with `asyncio`
- **DB Client**: `asyncpg` or `psycopg3`
- **MCP SDK**: `mcp` (official Python SDK)
- **Validation**: Pydantic 2.x
- **Testing**: pytest, pytest-asyncio, Testcontainers

### Infrastructure

**Docker Compose** (development/CI):
```yaml
services:
  postgres:
    image: postgres:18-alpine
    environment:
      POSTGRES_DB: cortex_dev
      POSTGRES_USER: cortex
      POSTGRES_PASSWORD: <generate>
    volumes:
      - ./schema.sql:/docker-entrypoint-initdb.d/01-schema.sql
```

**WSL2 Integration**: Docker Desktop with WSL2 backend for Windows developers.

---

## Development Workflow

### Test-Driven Development (MANDATORY)

**MUST** follow strict TDD cycle for all production code:

1. **Red**: Write failing test (unit or integration) that specifies expected behavior
2. **Green**: Implement minimal code to pass test
3. **Refactor**: Improve design while keeping tests green

**MUST** obtain explicit approval for test cases before implementation. No code written until tests are:
- Reviewed by user (if pair programming)
- Validated for correctness and coverage
- Confirmed to fail (Red phase)

### Testing Pyramid

**Unit Tests** (60% of coverage):
- Schema validation: valid/invalid payloads for each of 9 knowledge types
- Chunking logic: section splitting by heading/size limits
- Deduplication: `content_hash` collision detection
- Scope inference: branch detection from git context
- Ranking: formula correctness with mocked scores

**Integration Tests** (30% of coverage):
- Database round-trips: insert → query → verify
- FTS indexing: `ts_vector` generation and search
- TTL enforcement: expiration logic with time-mocked tests
- Audit logging: `event_audit` completeness checks
- Idempotency: duplicate `idempotency_key` handling

**E2E Tests** (10% of coverage):
- MCP protocol: STDIO transport with real server
- Golden path scenarios:
  - Feature find (spec/ADR retrieval)
  - Bugfix find (issue + runbook linking)
  - Store dedupe (duplicate section handling)
  - Branch isolation (cross-branch query rejection)
- Performance: P95 latency measurement (100K+ sections, Testcontainers)

### Vertical Slices & Incremental Delivery

**MUST** deliver features as vertical slices (UI → API → DB → tests) in smallest viable increments.

**MUST** submit pull requests per slice. Each PR:
- Implements ONE user story or sub-feature
- Includes tests (unit + integration minimum)
- Passes CI gates (lint, type-check, test, performance regression)
- Updates documentation (inline comments, README, CHANGELOG)

**MUST** keep tests green before refactoring. No speculative architecture; implement for current requirements (YAGNI).

### Code Review Requirements

**MUST** verify in every review:
- [ ] Constitution compliance (all 7 principles)
- [ ] Tests written first and failed before implementation
- [ ] Schema validation enforced (Zod/Pydantic)
- [ ] Audit logging present for mutations
- [ ] Performance SLO validation (P95 measurement if touching hot path)
- [ ] Idempotency handling (explicit `idempotency_key` or synthesized)
- [ ] Branch isolation preserved (no accidental cross-branch leaks)

---

## Governance

### Amendment Process

1. **Proposal**: Submit PR with constitutional changes + rationale
2. **Impact Analysis**: Document affected principles, templates, and code
3. **Approval**: Requires explicit sign-off from project lead
4. **Migration**: Update dependent templates (plan/spec/tasks), agent files, and code
5. **Version Bump**: Follow semantic versioning:
   - **MAJOR**: Breaking changes to principles (e.g., removing Principle III)
   - **MINOR**: Adding new principles or material expansions
   - **PATCH**: Clarifications, typo fixes, wording improvements

### Versioning Policy

Constitutional changes MUST increment version according to impact:
- Backward-incompatible governance changes → MAJOR bump
- New principles or sections → MINOR bump
- Clarifications without semantic changes → PATCH bump

### Compliance Review

**MUST** verify constitution compliance:
- **Pre-commit**: Automated checks for schema validation, audit logging presence
- **PR review**: Manual checklist verification (see Code Review Requirements)
- **Quarterly audit**: Review all ADRs, measure SLO actuals vs targets, assess technical debt

### Runtime Guidance

This constitution governs project-level decisions. For session-level development guidance, agents SHOULD consult:
- Global agent configuration (`C:\Users\Richard\.claude\CLAUDE.md`)
- Project-specific agent file (`.claude/CLAUDE.md` if present)
- Slash command templates (`.claude/commands/*.md`)

Constitution supersedes all other guidance in case of conflict.

---

**Version**: 1.0.0 | **Ratified**: 2025-10-09 | **Last Amended**: 2025-10-09
