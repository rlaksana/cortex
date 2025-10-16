# Research & Technical Decisions: Cortex Memory MCP v1

**Date**: 2025-10-09
**Phase**: 0 (Foundation & Research)
**Context**: Resolve technical unknowns before implementation begins

---

## Decision 1: Migration Strategy (Drizzle vs node-pg-migrate)

**Question**: Which migration tool to use for PostgreSQL schema management?

**Decision**: **Drizzle Kit** v0.20+

**Rationale**:
1. **Type Safety**: Drizzle generates TypeScript types from schema definitions, enabling compile-time validation and IntelliSense
2. **ORM Integration**: If later phases need ORM capabilities (e.g., complex JOIN queries), Drizzle ORM provides zero-cost abstraction over raw SQL
3. **Push vs Migrate**: Drizzle supports both `drizzle-kit push` (dev) and `drizzle-kit generate` + `migrate` (production)
4. **Schema-as-Code**: Define schema in TypeScript (src/db/schema.ts), migrations auto-generated
5. **Constitutional Alignment**: Type Safety principle (Principle VII) favors compile-time validation

**Alternatives Considered**:
- **node-pg-migrate**: Pure SQL migrations, more control but no type generation. Chosen if team prefers SQL-first approach and manual type definitions.
- **Kysely**: Type-safe query builder but requires separate migration tool (e.g., kysely-ctl). Two-tool complexity.

**Implementation Notes**:
- Use Drizzle schema definitions for 11 tables (document, section, runbook, pr_context, ddl_history, release_note, change_log, issue_log, adr_decision, todo_log, event_audit)
- Generate migrations: `drizzle-kit generate:pg`
- Apply migrations: `drizzle-kit push:pg` (dev) or custom migration runner (prod)
- Store migrations in `migrations/` directory per SOT DDL

---

## Decision 2: Section Chunking Strategy

**Question**: How to split large documentation sections into 1-3KB chunks?

**Decision**: **Heading-Based Chunking with Size Fallback**

**Rationale**:
1. **Semantic Coherence**: Splitting at headings (`##`, `###`, `####` in Markdown) preserves topic boundaries
2. **FTS Quality**: Smaller chunks improve Full-Text Search precision (match is within topic, not entire document)
3. **Relevance**: Users expect snippets to be self-contained (heading provides context)
4. **Constitutional Constraint**: FR-031 requires 1-3KB chunks, A-011 specifies heading-based strategy

**Algorithm**:
```
1. Parse Markdown for headings (ATX: ##, Setext: ===)
2. Split content at each heading boundary
3. For each chunk:
   a. If size ≤ 3KB: keep as-is
   b. If size > 3KB: further split by sub-headings or sentence boundaries
4. Ensure chunk >= 100 bytes (avoid tiny fragments)
5. Preserve heading text in chunk metadata (for context)
```

**Alternatives Considered**:
- **Sentence-Based**: Split at sentence boundaries (`.`, `?`, `!`). Loses topic coherence, harder to generate contextual snippets.
- **Fixed-Size**: Split at 1KB boundaries regardless of content. Breaks mid-sentence/mid-code-block, poor user experience.
- **Recursive Character Split**: LangChain-style recursive splitting. More complex, no significant benefit for documentation use case.

**Implementation Notes**:
- Library: `marked` (Markdown parser) to detect headings
- Store heading hierarchy in `section.heading` column
- Chunk size calculation: `Buffer.byteLength(text, 'utf8')`
- Fallback regex for sentence splits: `/(?<=[.!?])\s+(?=[A-Z])/`

---

## Decision 3: Content Hash Computation

**Question**: Use Node.js crypto or PostgreSQL pgcrypto for SHA-256 hashing?

**Decision**: **Node.js crypto module** (server-side hashing)

**Rationale**:
1. **Performance**: Compute hash once in application layer, not on every database query
2. **Idempotency Key Synthesis**: Hash needed before database insert (for dedupe check)
3. **Normalization Control**: Application layer can normalize text (trim whitespace, lowercase, remove punctuation) before hashing
4. **Audit Trail**: Hash computed value can be logged for debugging

**Algorithm**:
```typescript
import { createHash } from 'crypto';

function computeContentHash(text: string): string {
  const normalized = text
    .trim()
    .replace(/\s+/g, ' ')  // Collapse whitespace
    .toLowerCase();
  return createHash('sha256')
    .update(normalized, 'utf8')
    .digest('hex');
}
```

**Alternatives Considered**:
- **pgcrypto (database-side)**: Use `encode(digest(body_text, 'sha256'), 'hex')` in PostgreSQL. Requires hash recomputation on every SELECT if using virtual column. More DB load.
- **Stored Generated Column**: Pre-compute hash in Postgres during INSERT. Good for dedup queries but still requires server to know hash for idempotency check before insert.

**Implementation Notes**:
- Hash stored in `section.content_hash`, `change_log.content_hash` columns
- Dedupe query: `SELECT id FROM section WHERE content_hash = $1 LIMIT 1`
- Constitutional link: FR-032 requires SHA-256 for deduplication

---

## Decision 4: Scope Inference from Git Context

**Question**: How to infer `{org, project, branch}` scope when client doesn't provide it?

**Decision**: **Environment Variables** (fallback to git command)

**Rationale**:
1. **Simplicity**: MCP server receives env vars from host environment (e.g., Claude Code sets `CLAUDE_PROJECT_ROOT`, `CLAUDE_BRANCH`)
2. **No Dependencies**: Avoid libgit2 bindings (native module complexity)
3. **Performance**: Env var lookup is O(1), git command is subprocess overhead
4. **Constitutional Assumption**: A-001 documents this assumption

**Scope Resolution Strategy**:
```
1. Check env vars: CORTEX_ORG, CORTEX_PROJECT, CORTEX_BRANCH
2. Fallback to git:
   - org: extract from `git config --get remote.origin.url` (parse GitHub/GitLab URL)
   - project: basename of git root directory
   - branch: `git rev-parse --abbrev-ref HEAD`
3. If git unavailable: require explicit scope in request (return error if missing)
```

**Alternatives Considered**:
- **libgit2 (nodegit)**: Native bindings for git operations. High-quality but native module build complexity (WSL2 issues, Docker builds).
- **isomorphic-git**: Pure JavaScript git implementation. Slow for large repos, not needed for simple branch detection.
- **Explicit-Only**: Require scope in every request. Too strict, violates constitutional "infer when available" (FR-020).

**Implementation Notes**:
- Module: `src/utils/scope.ts`
- Function: `inferScope(): Promise<{org, project, branch}>`
- Cache result per server process (git branch doesn't change during MCP session)
- Error handling: If inference fails, log warning and require explicit scope

---

## Decision 5: Ranking Formula Implementation

**Question**: Should ranking formula be hardcoded or configurable?

**Decision**: **Hardcoded in v1** (configurable in future)

**Rationale**:
1. **Constitutional Constraint**: OS-009 marks custom formula configuration as Out of Scope for v1
2. **YAGNI**: No evidence of need for multi-formula support yet
3. **Performance**: Hardcoded formula compiles to optimized code path
4. **Simplicity**: Fewer configuration surfaces, easier to validate correctness

**Formula** (from constitution):
```
final_score = (0.4 × fts_score) + (0.3 × recency_boost) + (0.2 × scope_proximity) + (0.1 × citation_count)
```

**Component Calculations**:
- **fts_score**: `ts_rank(ts, query)` normalized to [0, 1]
- **recency_boost**: `1.0 - (log10(1 + days_since_update) / log10(180))` (1.0 @ 7d → 0.1 @ 180d)
- **scope_proximity**: 1.0 (exact branch), 0.5 (same project), 0.2 (cross-project)
- **citation_count**: `min(1.0, log10(1 + citation_count) / 2)` (logarithmic scaling)

**Alternatives Considered**:
- **Configurable Weights**: Allow users to adjust 0.4/0.3/0.2/0.1 weights via config file. Adds complexity, hard to validate quality.
- **ML-Based**: Train model on relevance feedback. Out of scope for v1, future extension (OS-003).
- **BM25**: Use BM25 instead of ts_rank. Requires custom implementation, PostgreSQL FTS is sufficient for v1.

**Implementation Notes**:
- Module: `src/services/ranker.ts`
- Function: `computeFinalScore(hit, context): number`
- Constitutional link: FR-024 specifies exact formula

---

## Decision 6: TTL Cleanup Strategy

**Question**: Cron job or PostgreSQL pg_cron extension for TTL cleanup?

**Decision**: **External Cron Job** (shell script + `psql`)

**Rationale**:
1. **Simplicity**: No PostgreSQL extension dependencies beyond pgcrypto + pg_trgm
2. **Observability**: Cron job can log to external system (e.g., syslog, monitoring)
3. **Flexibility**: Easy to reschedule, disable, or run manually for testing
4. **Constitutional Assumption**: A-009 documents cron-based cleanup

**Cleanup Script** (`scripts/ttl-cleanup.sh`):
```bash
#!/bin/bash
psql $DATABASE_URL <<EOF
-- Delete expired PR context (30d post-merge)
DELETE FROM pr_context WHERE expires_at < now();

-- Archive done/cancelled todos (90d after close)
UPDATE todo_log SET status = 'archived'
WHERE status IN ('done', 'cancelled')
  AND closed_at < now() - interval '90 days';

-- Flag stale runbooks (last_verified > 90d)
UPDATE runbook SET tags = jsonb_set(tags, '{stale}', 'true')
WHERE last_verified_at < now() - interval '90 days';

-- Vacuum and analyze hot tables
VACUUM ANALYZE section, change_log, issue_log, event_audit;
EOF
```

**Alternatives Considered**:
- **pg_cron**: PostgreSQL extension for scheduling. Requires superuser to install, not available in managed Postgres (e.g., RDS without extensions enabled).
- **Application-Side Scheduler**: Use `node-cron` or `node-schedule` in MCP server. Ties cleanup to server uptime, risky if server restarts frequently.
- **Lazy Deletion**: Delete on read (check TTL during query). Slows queries, doesn't reduce disk usage.

**Implementation Notes**:
- Schedule: Daily at 2 AM UTC (low traffic window)
- Crontab entry: `0 2 * * * /app/scripts/ttl-cleanup.sh >> /var/log/cortex-ttl.log 2>&1`
- Monitoring: Alert if cleanup duration > 5 minutes (indicates index/vacuum issues)

---

## Decision 7: Logging Structure (Pino Configuration)

**Question**: What log levels and fields should be captured?

**Decision**: **Structured JSON logging with trace IDs**

**Configuration**:
```typescript
import pino from 'pino';

export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  formatters: {
    level: (label) => ({ level: label }),
  },
  base: {
    service: 'cortex-mcp',
    environment: process.env.NODE_ENV || 'development',
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: {
    paths: ['*.idempotency_key', '*.actor'], // PII redaction
    remove: true,
  },
});
```

**Log Fields**:
- **request_id**: UUID v7 per MCP request (correlation)
- **tool_name**: `memory.find` or `memory.store`
- **sql_duration_ms**: Time spent in database queries
- **route_used**: `fts|semantic|graph`
- **result_count**: Number of hits returned
- **scope**: `{org, project, branch}` for audit

**Rationale**:
- JSON format enables log aggregation (ELK, Datadog)
- Trace IDs support distributed tracing (future extension)
- SQL timing identifies slow queries (performance monitoring)
- Redaction protects PII in audit logs

**Implementation Notes**:
- Attach logger to MCP request context
- Log at INFO for successful operations, ERROR for failures
- DEBUG level includes full request/response payloads (dev only)

---

## Decision 8: Testcontainers Configuration

**Question**: How to setup isolated Postgres 18 for E2E tests?

**Decision**: **Testcontainers with pg_trgm pre-installed**

**Configuration**:
```typescript
import { PostgreSqlContainer } from '@testcontainers/postgresql';

export async function startTestDb() {
  const container = await new PostgreSqlContainer('postgres:18-alpine')
    .withDatabase('cortex_test')
    .withUsername('test')
    .withPassword('test')
    .withExposedPorts(5432)
    .withStartupTimeout(60000)
    .start();

  const client = new Client({ connectionString: container.getConnectionString() });
  await client.connect();
  await client.query('CREATE EXTENSION IF NOT EXISTS pgcrypto;');
  await client.query('CREATE EXTENSION IF NOT EXISTS pg_trgm;');
  await client.end();

  return container;
}
```

**Rationale**:
- Real Postgres 18 (not mocked) for accurate integration tests
- Isolated per test suite (no cross-test pollution)
- Extensions installed automatically (pgcrypto + pg_trgm)
- Cleanup on teardown (no dangling containers)

**Implementation Notes**:
- Run migrations before each test suite: `await runMigrations(container.getConnectionString())`
- Seed minimal data: 1 document, 3 sections, 1 ADR, 1 issue
- Cleanup: `await container.stop()` in `afterAll` hook

---

## Decision 9: Performance Test Dataset Generation

**Question**: How to generate realistic 100K-1M section dataset for k6 tests?

**Decision**: **Synthetic data with Faker.js + real project structure**

**Strategy**:
```typescript
import { faker } from '@faker-js/faker';

async function generateSections(count: number) {
  const projects = ['cortex', 'andal-api', 'ui-kit', 'mobile-app'];
  const branches = ['main', 'develop', 'feature/auth', 'feature/search'];

  for (let i = 0; i < count; i++) {
    await client.query(`
      INSERT INTO section (id, document_id, heading, body_jsonb, content_hash, tags)
      VALUES (
        uuidv7(),
        $1,
        $2,
        jsonb_build_object('text', $3),
        encode(digest($3, 'sha256'), 'hex'),
        jsonb_build_object(
          'project', $4,
          'branch', $5,
          'service', $6
        )
      )
    `, [
      faker.string.uuid(),
      faker.lorem.sentence(),
      faker.lorem.paragraphs(3), // ~500-1000 bytes
      faker.helpers.arrayElement(projects),
      faker.helpers.arrayElement(branches),
      faker.helpers.arrayElement(['auth', 'search', 'api', 'db']),
    ]);
  }
}
```

**Rationale**:
- Faker generates realistic text (Lorem Ipsum alternative)
- Scope distribution matches real projects (4 projects × 4 branches = 16 combinations)
- FTS vectors populated (real search quality)
- Content hash distribution realistic (low collision rate)

**Implementation Notes**:
- Generate 100K for CI tests, 1M for local perf validation
- Pre-generate and store in SQL dump for CI caching
- Distribution: 70% sections, 15% changes, 10% issues, 5% ADRs/runbooks

---

## Summary of Research Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Migrations** | Drizzle Kit | Type safety, ORM integration, schema-as-code |
| **Chunking** | Heading-based + size fallback | Semantic coherence, FTS quality |
| **Hashing** | Node.js crypto | Performance, normalization control |
| **Scope Inference** | Env vars + git fallback | Simplicity, no native dependencies |
| **Ranking Formula** | Hardcoded | YAGNI, performance, constitutional constraint |
| **TTL Cleanup** | Cron job | Simplicity, no pg_cron dependency |
| **Logging** | Pino (JSON, trace IDs) | Structured logs, audit support |
| **Test DB** | Testcontainers | Real Postgres, isolated, repeatable |
| **Perf Dataset** | Faker.js synthetic | Realistic distribution, cached dumps |

**Next Phase**: Proceed to Phase 1 (Database Schema & Migrations) using these technical decisions.
