# Feature Specification: Cortex Memory MCP v1

**Feature Branch**: `001-create-specs-000`
**Created**: 2025-10-09
**Status**: Draft
**Input**: User description: "Ship Cortex Memory MCP v1: Minimal, Claude-friendly memory.find + memory.store with Postgres SoT, default branch isolation, full audit, and extensible cross-session memory. SoT is the gist (treat as authoritative)."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Store and Retrieve Cross-Session Knowledge (Priority: P1)

AI agents working on software projects need to persist knowledge (code sections, decisions, bugs, tasks) across sessions and retrieve it later when context is needed.

**Why this priority**: Core value proposition - without reliable storage and retrieval, the MCP provides no value. This is the foundational capability all other features depend on.

**Independent Test**: Can be fully tested by storing various knowledge items (sections, decisions, issues) via `memory.store`, then retrieving them via `memory.find` with different query patterns, and verifying correctness of returned results.

**Acceptance Scenarios**:

1. **Given** an AI agent is documenting an architecture decision, **When** it calls `memory.store` with kind=`decision` and complete required fields, **Then** the system returns success with a unique ID and status `inserted` or `updated`

2. **Given** knowledge items have been stored in previous sessions, **When** the agent calls `memory.find` with a relevant query, **Then** the system returns matching hits within 300ms with relevance scores and snippets

3. **Given** an agent stores the same content twice with identical idempotency key, **When** the second store is attempted, **Then** the system returns status `skipped_dedupe` without creating a duplicate

4. **Given** knowledge items exist across multiple knowledge types, **When** an agent searches without type filters, **Then** results include items from all relevant types ranked by relevance

---

### User Story 2 - Branch-Isolated Context Retrieval (Priority: P2)

AI agents working on feature branches need to see only their branch's context by default, preventing confusion from unrelated work in other branches, while allowing explicit cross-branch searches when needed.

**Why this priority**: Enables parallel development without context pollution. Critical for team workflows but depends on basic store/find (P1) working first.

**Independent Test**: Can be tested by storing items in different branch scopes, verifying that default searches return only current branch items, and confirming that explicit scope widening returns cross-branch results.

**Acceptance Scenarios**:

1. **Given** knowledge items exist in branches `feature-A` and `feature-B`, **When** an agent on `feature-A` calls `memory.find` with default scope, **Then** only `feature-A` items are returned

2. **Given** an agent needs to reference decisions from the main branch, **When** it calls `memory.find` with explicit scope widening (e.g., `scope.branch: "main"`), **Then** results include items from the specified branch

3. **Given** items exist at different scope levels (org, project, service, branch), **When** searching with partial scope specification, **Then** results are ranked by scope proximity (exact branch match scores highest)

---

### User Story 3 - Comprehensive Audit and Immutability (Priority: P3)

Teams need complete audit trails of all knowledge mutations and enforcement of immutability rules (e.g., accepted ADRs cannot be modified) for compliance and reliability.

**Why this priority**: Important for production deployments and compliance, but core functionality (P1, P2) must work first. Can be validated after basic storage/retrieval is proven.

**Independent Test**: Can be tested by attempting to modify immutable content (accepted ADRs, approved specs), storing various items and verifying audit entries, and confirming 100% mutation coverage in audit logs.

**Acceptance Scenarios**:

1. **Given** an Architecture Decision Record (ADR) has status `accepted`, **When** an agent attempts to modify its content, **Then** the system rejects the modification and returns an error indicating immutability

2. **Given** any mutation operation occurs (store, update, delete), **When** the operation completes, **Then** an audit entry is created in the audit log with actor, timestamp, and change details

3. **Given** a specification has been marked as approved, **When** an agent attempts to store an updated version without version bump, **Then** the system enforces write-lock and rejects the change

4. **Given** audit log entries exist, **When** queried, **Then** 100% of mutations are represented with no gaps or missing entries

---

### User Story 4 - Intelligent Search with Routing and Suggestions (Priority: P3)

AI agents benefit from server-side intelligence that routes queries to optimal search strategies (FTS vs deep semantic) and provides helpful suggestions when initial search yields low results.

**Why this priority**: Enhances user experience but requires core search (P1) to be functional. Routing optimizations can be added iteratively.

**Independent Test**: Can be tested by submitting queries with different modes (`auto`, `fast`, `deep`), verifying appropriate route selection, measuring latency differences, and confirming suggestions appear for low-recall queries.

**Acceptance Scenarios**:

1. **Given** an agent submits a query with `mode="auto"`, **When** the query contains issue IDs or PR references, **Then** the server routes to logs-first strategy and includes `route_used` in response

2. **Given** a search returns fewer than 3 results, **When** the system detects low recall, **Then** response includes helpful suggestions for refining the query

3. **Given** an agent uses `mode="fast"`, **When** the query executes, **Then** P95 latency is under 100ms using FTS-only search

4. **Given** an agent uses `mode="deep"` on complex queries, **When** the query executes, **Then** fuzzy matching and similarity search are applied with P95 latency under 300ms

---

### Edge Cases

- **Empty query string**: How does system handle `memory.find` with empty or whitespace-only query?
- **Malformed scope**: What happens when scope contains invalid combinations (e.g., tenant without org)?
- **Concurrent modifications**: How does system handle simultaneous stores of the same content from multiple sessions?
- **TTL expiration during query**: What happens if an item's TTL expires between search execution and result return?
- **Missing required extensions**: How does system behave if `pg_trgm` extension is not installed?
- **Content hash collisions**: What is the behavior if two different contents produce the same SHA-256 hash (theoretical)?
- **Scope inference failure**: What happens when git context is unavailable and scope cannot be inferred?
- **Audit log storage failure**: How does system handle mutations when audit logging fails?

## Requirements *(mandatory)*

### Functional Requirements

**Core API Requirements**

- **FR-001**: System MUST expose exactly two MCP tools: `memory.find` and `memory.store` with JSON schemas matching SOT specification exactly
- **FR-002**: System MUST implement `memory.find` with parameters: `query` (required), `scope`, `types`, `top_k`, `mode`, `time_range`
- **FR-003**: System MUST implement `memory.store` with parameter `items[]` where each item has: `kind` (required), `scope` (required), `data` (required), `tags`, `source`, `idempotency_key`, `ttl_policy`
- **FR-004**: `memory.find` responses MUST include: `hits[]` array, optional `suggestions[]`, optional `debug` object
- **FR-005**: Each hit in `memory.find` MUST include: `kind`, `id`, `snippet`, `score`, and MAY include `title`, `tags`, `last_verified`, `route_used`, `confidence`, `citations[]`
- **FR-006**: `memory.store` responses MUST include: `stored[]` array with status (`inserted`, `updated`, `skipped_dedupe`), optional `errors[]` array

**Knowledge Type Requirements**

- **FR-007**: System MUST support exactly 9 knowledge types: `section`, `runbook`, `change`, `issue`, `decision`, `todo`, `release_note`, `ddl`, `pr_context`
- **FR-008**: For `section` kind, data MUST include: `title` (string), and either `body_md` OR `body_text` (string)
- **FR-009**: For `runbook` kind, data MUST include: `service` (string), `steps` (array)
- **FR-010**: For `change` kind, data MUST include: `change_type` (enum: code|schema|config|runbook|infra), `subject_ref` (json), `summary` (string)
- **FR-011**: For `issue` kind, data MUST include: `tracker` (string), `external_id` (string), `title` (string), `status` (string)
- **FR-012**: For `decision` kind, data MUST include: `component` (string), `status` (enum: proposed|accepted|deprecated|superseded), `title` (string), `rationale` (json), `alternatives[]`
- **FR-013**: For `todo` kind, data MUST include: `scope` (enum: user|project|service|branch), `todo_type` (enum: feature|bugfix|ops|doc), `text` (string)
- **FR-014**: For `release_note` kind, data MUST include: `version` (string), `highlights[]` (array)
- **FR-015**: For `ddl` kind, data MUST include: `entity` (string), `ddl_sql` (string)
- **FR-016**: For `pr_context` kind, data MUST include: `pr_id` (string), `repo` (string), `files[]` (json), `findings[]` (json)

**Scope and Isolation Requirements**

- **FR-017**: System MUST support six-level hierarchical scope: `org`, `project`, `service`, `branch`, `sprint`, `tenant`
- **FR-018**: System MUST default to branch-isolated reads using caller's `{org, project, branch}` scope
- **FR-019**: System MUST allow explicit scope widening when client provides broader scope parameters
- **FR-020**: System MUST infer missing scope values from git context when available
- **FR-021**: System MUST apply scope proximity scoring: 1.0 for exact branch match, 0.5 for same project/different branch, 0.2 for cross-project

**Search and Ranking Requirements**

- **FR-022**: System MUST support three search modes: `auto` (default), `fast`, `deep`
- **FR-023**: In `auto` mode, system MUST route queries intelligently: issue/PR IDs → logs-first, file/symbol/stack → runbook+sections, "implement/design/why" → specs/ADR/examples
- **FR-024**: System MUST calculate final ranking score using formula: `(0.4 × fts_score) + (0.3 × recency_boost) + (0.2 × scope_proximity) + (0.1 × citation_count)`
- **FR-025**: System MUST apply recency boost: 1.0 if modified within 7 days, decaying to 0.1 after 180 days (except immutable ADRs)
- **FR-026**: System MUST support `top_k` parameter to limit result count (default: 20)
- **FR-027**: System MUST support `time_range` filtering with `since` and `until` date-time parameters
- **FR-028**: System MUST support filtering by knowledge types via `types[]` array parameter
- **FR-029**: System MUST include `route_used` (enum: fts|semantic|graph) and `confidence` score in search results
- **FR-030**: System MUST provide suggestions when search recall is low (fewer than 3 relevant results)

**Storage and Deduplication Requirements**

- **FR-031**: System MUST handle chunking of large sections (split to 1-3KB chunks) server-side
- **FR-032**: System MUST compute `content_hash` using SHA-256 for deduplication
- **FR-033**: System MUST implement idempotent writes using provided `idempotency_key` or synthesized `{kind, scope, source, content_hash}` composite
- **FR-034**: System MUST return status `skipped_dedupe` when duplicate content is detected
- **FR-035**: System MUST create exactly one audit entry on first insertion (not on duplicate skips)

**Immutability and Audit Requirements**

- **FR-036**: System MUST enforce immutability: ADR content with status `accepted` becomes read-only
- **FR-037**: System MUST enforce immutability: approved specifications are write-locked (changes require version bump + re-approval)
- **FR-038**: System MUST maintain append-only `event_audit` table (no updates or deletes permitted)
- **FR-039**: System MUST log 100% of mutations (store, update, delete operations) to audit log
- **FR-040**: System MUST include in audit entries: actor, timestamp, operation type, affected entity ID, change details

**TTL and Lifecycle Requirements**

- **FR-041**: System MUST support TTL policies: `PR30d` (30 days post-merge), `BRANCH90d` (90 days), `NONE` (perpetual)
- **FR-042**: System MUST auto-expire `pr_context` items 30 days after PR merge
- **FR-043**: System MUST flag `runbook` items where `last_verified_at` exceeds 90 days
- **FR-044**: System MUST support background cleanup process for expired TTL items

**Database and Performance Requirements**

- **FR-045**: System MUST use PostgreSQL 18 or higher as exclusive source of truth
- **FR-046**: System MUST require and verify presence of extensions: `pgcrypto`, `pg_trgm`
- **FR-047**: System MUST use `uuidv7()` for all new entity IDs
- **FR-048**: System MUST create GIN indexes for: full-text search vectors, JSONB tags, pg_trgm similarity
- **FR-049**: System MUST achieve P95 latency < 300ms for `memory.find` on datasets ≤ 1–3M sections
- **FR-050**: System MUST achieve P95 latency < 100ms for `mode="fast"` queries
- **FR-051**: System MUST maintain Top-3 relevance ≥ 80% (sampled evaluation)

**Error Handling Requirements**

- **FR-052**: System MUST validate all required fields before storage and return structured errors for missing fields
- **FR-053**: System MUST return error responses with: `error_code` (enum), `human_hint` (string), optional `fix` (object)
- **FR-054**: System MUST support error codes: `MISSING_FIELDS`, `INVALID_SCOPE`, `UNAUTHORIZED`, `RATE_LIMIT`, `CONFLICT`
- **FR-055**: System MUST provide actionable human-readable hints for all error conditions

### Key Entities

- **Section**: Documentation fragments representing chunks of technical documentation, specs, or guides. Attributes include title, heading hierarchy, body content (markdown or plain text), content hash for deduplication. Perpetual storage with no TTL expiration.

- **Runbook**: Operational procedures documenting how to perform specific service tasks. Attributes include service name, ordered steps array, last verification timestamp. Requires manual verification every 90 days (flagged if stale).

- **Change**: Records of code, schema, config, or infrastructure modifications. Attributes include change type discriminator, subject reference (entity being changed), summary, optional impact level, breaking change risk indicator, PR/commit references. Branch-scoped with 90-day TTL.

- **Issue**: Synchronized records from external bug/feature trackers. Attributes include tracker identifier, external ID, title, status, optional severity, assignee, labels, linked PR IDs. Perpetual storage until closed + 90 days.

- **Decision**: Architecture Decision Records (ADRs) documenting significant technical choices. Attributes include component scope, status (proposed/accepted/deprecated/superseded), title, rationale (structured), alternatives considered, supersedes relationship. Immutable once accepted.

- **Todo**: Cross-session task tracking for user, project, service, or branch scopes. Attributes include scope level, todo type (feature/bugfix/ops/doc), text description, optional priority and due date. Branch-scoped with 90-day default TTL.

- **Release Note**: Deployment and release artifact documentation. Attributes include version identifier, highlights array. Perpetual storage for release history.

- **DDL**: Database schema definitions with backward compatibility tracking. Attributes include entity name, DDL SQL statement, optional breaking change check metadata. Perpetual storage for schema evolution history.

- **PR Context**: Pull request analysis cache containing file changes and automated findings. Attributes include PR ID, repository, files array, findings array, expiration timestamp. Auto-expires 30 days post-merge.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Search queries return results within 300 milliseconds for 95% of requests on datasets containing up to 3 million documentation sections

- **SC-002**: Top 3 search results are relevant to the query for at least 80% of searches (measured via sampled human evaluation)

- **SC-003**: Agents working on feature branches see only their branch's context by default, with zero cross-branch pollution in isolated searches

- **SC-004**: All data modification operations (100%) are recorded in audit logs with complete metadata (actor, timestamp, change details)

- **SC-005**: Duplicate content submissions are detected and rejected, returning deduplication status without creating database duplicates

- **SC-006**: Accepted architecture decisions cannot be modified, and attempts to do so are rejected with clear error messages

- **SC-007**: Search queries using fast mode return results within 100 milliseconds for 95% of requests

- **SC-008**: System provides helpful query suggestions when fewer than 3 relevant results are found

- **SC-009**: Scope-widened searches successfully return results from specified branches/projects when explicitly requested

- **SC-010**: Invalid inputs (missing required fields, malformed scope) are rejected with actionable error messages before database writes

## Assumptions *(document decisions made in absence of full specification)*

- **A-001**: Git context (current branch, org, project) is available to the MCP server through environment variables or configuration. If unavailable, explicit scope must be provided by client.

- **A-002**: "Relevant" for SC-002 Top-3 evaluation will be defined as: human evaluator agrees the result addresses the query intent and provides useful information for the task context.

- **A-003**: PostgreSQL 18 is available and `pg_trgm` extension can be installed. DoltgreSQL is not supported in v1 due to lack of `pg_trgm` support.

- **A-004**: MCP server runs as a single-instance process communicating via STDIO (JSON-RPC 2.0). Horizontal scaling is out of scope for v1.

- **A-005**: Authentication and authorization are handled externally (by the MCP host environment). The server assumes all requests are authenticated and authorized.

- **A-006**: "Post-merge" for PR context TTL means the PR has been closed/merged in the external tracker, detected via periodic sync or webhook.

- **A-007**: Recency scoring decay uses a logarithmic function from 7 days (1.0) to 180 days (0.1) to balance recent vs historical content.

- **A-008**: Citation count refers to the number of times a knowledge item is referenced by other items (e.g., an ADR cited in multiple changes).

- **A-009**: Background TTL cleanup runs as a scheduled task (e.g., daily cron job) and does not impact query performance.

- **A-010**: "Sampled evaluation" for SC-002 means a statistically significant random sample (e.g., 100-200 queries) evaluated manually or via LLM-assisted relevance scoring.

- **A-011**: Section chunking splits content at heading boundaries when possible, falling back to size-based splits (1-3KB) to maintain semantic coherence.

- **A-012**: `mode="auto"` routing heuristics use pattern matching on query text (issue IDs, file paths, intent keywords) to select optimal search strategy.

## Dependencies

- **D-001**: PostgreSQL 18+ database instance with `pgcrypto` and `pg_trgm` extensions enabled
- **D-002**: MCP SDK (TypeScript or Python) for STDIO transport and JSON-RPC protocol
- **D-003**: Schema validation library (Zod for TypeScript, Pydantic for Python) matching the 9 knowledge type schemas
- **D-004**: Git environment or configuration providing current branch/org/project context
- **D-005**: SOT specification from gist (https://gist.github.com/rlaksana/d794a4623cb1b6155c70ec4b62e72f8b) as authoritative reference for all schema definitions
- **D-006**: Constitution file (`.specify/memory/constitution.md`) defining governance and compliance requirements

## Out of Scope

- **OS-001**: Vector search via Qdrant (future extension, v2+)
- **OS-002**: Graph traversal via Neo4j (future extension, v2+)
- **OS-003**: ML-based reranking and relevance tuning (future enhancement)
- **OS-004**: Horizontal scaling and multi-instance deployment (v1 is single-instance)
- **OS-005**: Real-time collaboration features (multiple agents editing same knowledge concurrently)
- **OS-006**: User interface or web dashboard (v1 is API-only)
- **OS-007**: External tracker integrations beyond basic issue sync schema
- **OS-008**: Automated relevance testing framework (SC-002 evaluation is manual/semi-automated)
- **OS-009**: Custom ranking formula configuration (v1 uses fixed formula from constitution)
- **OS-010**: Binary content storage (images, PDFs, etc. - v1 supports text only)
