# Data Model: Cortex Memory MCP v1

**Date**: 2025-10-09
**Phase**: 1 (Database Schema & Migrations)
**Database**: PostgreSQL 18+ with `pgcrypto` + `pg_trgm` extensions

---

## Overview

Cortex Memory MCP uses 11 PostgreSQL tables organized into 4 categories:

1. **Core Documentation** (2 tables): document, section
2. **Operational Knowledge** (3 tables): runbook, pr_context, ddl_history
3. **Four Logs** (4 tables): change_log, issue_log, adr_decision, todo_log
4. **Audit Trail** (2 tables): release_note, event_audit

All tables use `uuidv7()` for primary keys (time-ordered UUIDs) except `event_audit` which uses `bigserial`.

---

## Table Definitions

### 1. document
**Purpose**: Container for specifications, guides, and documentation

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | uuid | PK, default uuidv7() | Unique document identifier |
| type | text | NOT NULL, CHECK(spec\|doc\|guide\|other) | Document classification |
| title | text | NOT NULL | Human-readable title |
| tags | jsonb | NOT NULL, default '{}' | Scope metadata (org, project, branch, service) |
| approved_at | timestamptz | NULL | Approval timestamp (write-lock trigger fires when set) |
| created_at | timestamptz | NOT NULL, default now() | Creation timestamp |
| updated_at | timestamptz | NOT NULL, default now() | Last modification timestamp (auto-updated by trigger) |

**Triggers**:
- `t_document_touch`: Auto-update `updated_at` on UPDATE
- `t_doc_approved_lock`: Prevent updates when `approved_at IS NOT NULL` (immutability)
- `t_audit_document`: Log all INSERT/UPDATE/DELETE to event_audit

**Indexes**: None (small table, queried by PK only)

---

### 2. section
**Purpose**: Documentation chunks (1-3KB) with full-text search vectors

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | uuid | PK, default uuidv7() | Unique section identifier |
| document_id | uuid | FK → document(id) ON DELETE CASCADE | Parent document |
| heading | text | NULL | Section heading (for context in snippets) |
| body_jsonb | jsonb | NOT NULL | Section content (Markdown or plain text) |
| body_text | text | GENERATED ALWAYS AS ((body_jsonb->>'text')) STORED | Extracted plain text for FTS |
| content_hash | text | NOT NULL | SHA-256 hash for deduplication |
| tags | jsonb | NOT NULL, default '{}' | Scope metadata (org, project, branch, service) |
| last_verified_at | timestamptz | NULL | Last manual verification (flagged if >90d) |
| created_at | timestamptz | NOT NULL, default now() | Creation timestamp |
| updated_at | timestamptz | NOT NULL, default now() | Last modification timestamp |
| ts | tsvector | GENERATED ALWAYS AS (setweight(...)) STORED | Full-text search vector (heading='A', body='B') |

**Triggers**:
- `t_section_touch`: Auto-update `updated_at` on UPDATE
- `t_audit_section`: Log all mutations to event_audit

**Indexes**:
- `section_fts_idx`: GIN index on `ts` (full-text search)
- `section_tags_gin`: GIN index on `tags` (scope filtering)
- `section_body_gin`: GIN index on `body_jsonb` using `jsonb_path_ops` (fast containment queries)

**Relationships**:
- **Parent**: document (CASCADE delete)

---

### 3. runbook
**Purpose**: Operational procedures with verification tracking

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | uuid | PK, default uuidv7() | Unique runbook identifier |
| service | text | NOT NULL | Service name (e.g., "auth-api", "payment-gateway") |
| steps_jsonb | jsonb | NOT NULL | Ordered array of steps [{step: 1, action: "...", ...}] |
| last_verified_at | timestamptz | NULL | Last manual verification (flagged if >90d) |
| owner | text | NULL | Team/person responsible |
| tags | jsonb | NOT NULL, default '{}' | Scope metadata |
| created_at | timestamptz | NOT NULL, default now() | Creation timestamp |
| updated_at | timestamptz | NOT NULL, default now() | Last modification timestamp |

**Triggers**:
- `t_runbook_touch`: Auto-update `updated_at` on UPDATE
- `t_audit_runbook`: Log all mutations to event_audit

**Indexes**:
- `runbook_tags_gin`: GIN index on `tags` (scope filtering)

---

### 4. pr_context
**Purpose**: Pull request analysis cache with 30-day TTL

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | uuid | PK, default uuidv7() | Unique PR context identifier |
| pr_id | text | NOT NULL | External PR identifier (e.g., "123", "ADO-456") |
| repo | text | NOT NULL | Repository identifier (e.g., "org/repo") |
| files_jsonb | jsonb | NOT NULL, default '[]' | Changed files [{path, additions, deletions}] |
| findings_jsonb | jsonb | NOT NULL, default '[]' | Analysis results [{type, severity, message}] |
| expires_at | timestamptz | NOT NULL | TTL expiration (30 days post-merge) |
| tags | jsonb | NOT NULL, default '{}' | Scope metadata |
| created_at | timestamptz | NOT NULL, default now() | Creation timestamp |

**Triggers**:
- `t_audit_pr_context`: Log all mutations to event_audit

**Indexes**: None (queried by pr_id, small table, TTL cleanup removes old entries)

**TTL Cleanup**: Cron job deletes entries where `expires_at < now()`

---

### 5. ddl_history
**Purpose**: Database schema evolution log

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | uuid | PK, default uuidv7() | Unique DDL record identifier |
| service | text | NOT NULL | Service name |
| entity | text | NOT NULL | Table/index/constraint name |
| ddl_sql | text | NOT NULL | DDL statement (CREATE/ALTER/DROP) |
| bc_check_jsonb | jsonb | NOT NULL, default '{}' | Breaking change check metadata |
| applied_at | timestamptz | NOT NULL, default now() | Application timestamp |
| tags | jsonb | NOT NULL, default '{}' | Scope metadata |

**Triggers**:
- `t_audit_ddl_history`: Log all mutations to event_audit

**Indexes**: None (append-only, queried by service+entity)

---

### 6. release_note
**Purpose**: Deployment and release artifact documentation

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | uuid | PK, default uuidv7() | Unique release note identifier |
| tag | text | NOT NULL | Version tag (e.g., "v1.2.3", "2025-01-15-deploy") |
| notes_md | text | NOT NULL | Release notes in Markdown |
| risk_jsonb | jsonb | NOT NULL, default '{}' | Risk assessment metadata |
| ack_by | text | NULL | Acknowledgment/approval by (person/team) |
| created_at | timestamptz | NOT NULL, default now() | Creation timestamp |
| tags | jsonb | NOT NULL, default '{}' | Scope metadata |

**Triggers**:
- `t_audit_release_note`: Log all mutations to event_audit

**Indexes**: None (small table, queried by tag)

---

### 7. change_log
**Purpose**: Code/schema/config/runbook/infra modification tracking

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | uuid | PK, default uuidv7() | Unique change identifier |
| project | text | NOT NULL | Project name |
| service | text | NOT NULL | Service name |
| branch | text | NOT NULL | Git branch |
| change_type | text | NOT NULL, CHECK(code\|schema\|config\|runbook\|infra) | Change category |
| subject_ref | jsonb | NOT NULL | Subject reference (file path, entity name, etc.) |
| summary | text | NOT NULL | Human-readable change summary |
| impact_level | text | CHECK(low\|med\|high) | Impact assessment |
| bc_risk | boolean | default false | Breaking change risk flag |
| pr_id | text | NULL | Pull request identifier |
| commit_sha | text | NULL | Git commit SHA |
| links | jsonb | NOT NULL, default '{}' | References to issues, ADRs, runbooks |
| status | text | NOT NULL, default 'draft', CHECK(draft\|applied\|reverted) | Lifecycle status |
| parent_change_id | uuid | FK → change_log(id) | Parent change (for reverts/amendments) |
| tags | jsonb | NOT NULL, default '{}' | Additional metadata |
| content_hash | text | NOT NULL | SHA-256(subject_ref + summary) for deduplication |
| created_by | text | NOT NULL | Actor (user/service) |
| created_at | timestamptz | NOT NULL, default now() | Creation timestamp |

**Triggers**:
- `t_audit_change_log`: Log all mutations to event_audit

**Indexes**:
- `change_log_pr_commit_uq`: UNIQUE index on (pr_id, commit_sha) WHERE both NOT NULL
- `change_log_scope_idx`: Multi-column index on (project, service, branch, created_at DESC) - benefits from skip-scan
- `change_log_tags_gin`: GIN index on `tags`

**Relationships**:
- **Self-referential**: parent_change_id → change_log(id)

---

### 8. issue_log
**Purpose**: Bug/feature tracker synchronization

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | uuid | PK, default uuidv7() | Unique issue identifier |
| tracker | text | NOT NULL, CHECK(azure\|github\|jira\|other) | External tracker type |
| external_id | text | NOT NULL | Tracker-specific ID (e.g., "ADO-123", "#456") |
| project | text | NOT NULL | Project name |
| service | text | NULL | Service name (optional for project-wide issues) |
| title | text | NOT NULL | Issue title |
| severity | text | CHECK(S1\|S2\|S3\|S4) | Severity classification |
| status | text | NOT NULL, CHECK(open\|in_progress\|blocked\|done\|won't_fix) | Lifecycle status |
| assignee | text | NULL | Assigned person/team |
| labels | jsonb | NOT NULL, default '[]' | Issue labels/tags |
| linked_prs | jsonb | NOT NULL, default '[]' | Linked PR identifiers |
| created_at | timestamptz | NOT NULL, default now() | Creation timestamp |
| closed_at | timestamptz | NULL | Closure timestamp |
| tags | jsonb | NOT NULL, default '{}' | Additional metadata |

**Triggers**:
- `t_audit_issue_log`: Log all mutations to event_audit

**Indexes**:
- **UNIQUE**: (tracker, external_id) - prevents duplicate sync
- `issue_log_scope_idx`: Multi-column index on (project, service, status)
- `issue_log_labels_gin`: GIN index on `labels`
- `issue_log_tags_gin`: GIN index on `tags`

---

### 9. adr_decision
**Purpose**: Architecture Decision Records (immutable once accepted)

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | uuid | PK, default uuidv7() | Unique ADR identifier |
| project | text | NOT NULL | Project name |
| component | text | NOT NULL | Component/service scope |
| status | text | NOT NULL, CHECK(proposed\|accepted\|deprecated\|superseded) | Decision lifecycle status |
| title | text | NOT NULL | Decision title (immutable once accepted) |
| rationale | jsonb | NOT NULL | Structured rationale (immutable once accepted) |
| alternatives | jsonb | NOT NULL, default '[]' | Alternatives considered (immutable once accepted) |
| decided_by | text | NULL | Decision maker (person/team) |
| decided_at | timestamptz | NOT NULL, default now() | Decision timestamp |
| supersedes | uuid | FK → adr_decision(id) | Superseded ADR (when status='superseded') |
| tags | jsonb | NOT NULL, default '{}' | Additional metadata |

**Triggers**:
- `t_adr_immutable`: **BEFORE UPDATE** - Prevents changes to `title`, `rationale`, `alternatives` if status was/is 'accepted' (constitutional immutability)
- `t_audit_adr_decision`: Log all mutations to event_audit

**Indexes**:
- `adr_decision_scope_idx`: Multi-column index on (project, component, status, decided_at DESC)

**Relationships**:
- **Self-referential**: supersedes → adr_decision(id)

**Immutability Enforcement**: Once status='accepted', content fields are read-only. Amendments create new ADR with `supersedes` link.

---

### 10. todo_log
**Purpose**: Cross-session task tracking

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | uuid | PK, default uuidv7() | Unique todo identifier |
| scope | text | NOT NULL, CHECK(user\|project\|service\|branch) | Scope level |
| project | text | NULL | Project name (required for project/service/branch scope) |
| service | text | NULL | Service name (required for service scope) |
| branch | text | NULL | Branch name (required for branch scope) |
| todo_type | text | NOT NULL, CHECK(feature\|bugfix\|ops\|doc) | Task category |
| text | text | NOT NULL | Task description |
| priority | int | NOT NULL, default 3 | Priority (1=high, 5=low) |
| due_at | timestamptz | NULL | Due date/time |
| status | text | NOT NULL, default 'open', CHECK(open\|in_progress\|blocked\|done\|cancelled) | Lifecycle status |
| created_by | text | NOT NULL | Creator (user/agent) |
| created_at | timestamptz | NOT NULL, default now() | Creation timestamp |
| closed_at | timestamptz | NULL | Closure timestamp |
| source | jsonb | NOT NULL, default '{}' | Source metadata (issue ID, PR, etc.) |
| order_index | numeric | default 0 | Display order (for manual sorting) |
| tags | jsonb | NOT NULL, default '{}' | Additional metadata |

**Triggers**:
- `t_audit_todo_log`: Log all mutations to event_audit

**Indexes**:
- `todo_scope_idx`: Multi-column index on (status, priority, due_at) - optimized for active task queries

**TTL Cleanup**: Cron job archives done/cancelled todos 90 days after `closed_at`

---

### 11. event_audit
**Purpose**: Append-only audit trail for all mutations (constitutional requirement)

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | bigserial | PK | Auto-incrementing audit entry ID |
| at | timestamptz | NOT NULL, default now() | Event timestamp |
| actor | text | NOT NULL | Actor (current_user or service) |
| action | text | NOT NULL | Operation type (INSERT\|UPDATE\|DELETE) |
| entity_type | text | NOT NULL | Table name |
| entity_id | uuid | NULL | Affected entity PK |
| project | text | NULL | Extracted from entity tags |
| service | text | NULL | Extracted from entity tags |
| branch | text | NULL | Extracted from entity tags |
| request_id | text | NULL | MCP request correlation ID |
| session_id | text | NULL | MCP session ID |
| tool_name | text | NULL | MCP tool name (memory.find\|memory.store) |
| confidence | real | NULL | Search confidence score (for memory.find audits) |
| before | jsonb | NULL | Full row before UPDATE/DELETE |
| after | jsonb | NULL | Full row after INSERT/UPDATE |

**Triggers**: None (this table is the audit target)

**Indexes**:
- `event_audit_idx`: Multi-column index on (entity_type, entity_id, at) - optimized for entity history queries

**Immutability**: Constitutional requirement (Principle IV) - no UPDATE or DELETE operations permitted. Append-only.

---

## Entity Relationship Diagram (ERD)

```
┌─────────────┐
│  document   │
│  (id: PK)   │──┐
└─────────────┘  │ 1:N (CASCADE)
                 │
                 ▼
            ┌─────────────┐
            │   section   │
            │  (id: PK)   │
            │ document_id │
            └─────────────┘

┌─────────────┐
│   runbook   │
│  (id: PK)   │ (standalone)
└─────────────┘

┌─────────────┐
│ pr_context  │
│  (id: PK)   │ (standalone, TTL=30d)
└─────────────┘

┌─────────────┐
│ ddl_history │
│  (id: PK)   │ (standalone)
└─────────────┘

┌──────────────┐
│ release_note │
│  (id: PK)    │ (standalone)
└──────────────┘

┌──────────────┐
│  change_log  │──┐
│  (id: PK)    │  │ self-reference
│parent_change_│◄─┘ (reverts/amendments)
└──────────────┘

┌──────────────┐
│  issue_log   │
│  (id: PK)    │ (standalone)
│ UNIQUE(track │ unique per external tracker
│ er,external_ │
│ id)          │
└──────────────┘

┌──────────────┐
│adr_decision  │──┐
│  (id: PK)    │  │ self-reference
│  supersedes  │◄─┘ (ADR amendments)
└──────────────┘

┌──────────────┐
│  todo_log    │
│  (id: PK)    │ (standalone)
└──────────────┘

┌──────────────┐
│ event_audit  │ (audit target, NO FK)
│  (id: PK)    │ Logs mutations from ALL tables
└──────────────┘
```

**Relationship Notes**:
- **document → section**: 1:N with CASCADE delete (deleting document removes all sections)
- **change_log → change_log**: Self-referential for revert/amendment tracking
- **adr_decision → adr_decision**: Self-referential for ADR supersession
- **event_audit**: No foreign keys (stores entity_type + entity_id as text/uuid pair)

---

## Scope Metadata Pattern

All 10 knowledge tables (except event_audit) use `tags` JSONB column for 6-level scope hierarchy:

```json
{
  "org": "acme-corp",
  "project": "cortex-mcp",
  "service": "auth-api",
  "branch": "feature/oauth",
  "sprint": "2025-Q1-S3",
  "tenant": "customer-123"
}
```

**Branch Isolation** (constitutional requirement): Queries default to filtering by `tags->>'branch' = $current_branch`.

**Scope Proximity Scoring** (ranking formula):
- Exact branch match: 1.0
- Same project, different branch: 0.5
- Cross-project: 0.2

---

## Deduplication Strategy

| Table | Dedupe Field | Strategy |
|-------|--------------|----------|
| section | content_hash | SHA-256(normalized body_text) |
| change_log | content_hash | SHA-256(subject_ref + summary) |
| issue_log | (tracker, external_id) | UNIQUE constraint |
| pr_context | (pr_id, repo) | Application-level check |
| Others | N/A | No deduplication (append-only or manual edits) |

---

## Migration Files

**001_initial_schema.sql**: CREATE TABLE statements for all 11 tables

**002_indexes.sql**: CREATE INDEX statements for GIN, multi-column, and unique indexes

**003_triggers.sql**: CREATE TRIGGER statements for:
- `touch_updated_at` (document, section, runbook)
- `adr_immutable` (adr_decision)
- `approved_lock` (document)
- `audit_row` (all 10 knowledge tables)

**Execution Order**: 001 → 002 → 003 (indexes after tables, triggers after indexes)

---

## Performance Considerations

**Postgres 18 Features Used**:
1. **uuidv7()**: Time-ordered UUIDs improve INSERT performance (clustered writes)
2. **Skip Scan Optimization**: Multi-column indexes efficient even when leading columns omitted
3. **Generated Columns**: `body_text` (stored), `ts` (stored) computed once at write-time
4. **GIN Indexes**: Fast JSONB containment, FTS, and pg_trgm similarity queries

**Index Strategy**:
- GIN for all JSONB `tags` columns (scope filtering)
- GIN for FTS `ts` vector (full-text search)
- GIN for `body_jsonb` with `jsonb_path_ops` (fast containment)
- Multi-column indexes for common query patterns (project+service+branch+time)
- UNIQUE constraints for deduplication (issue_log, change_log)

**Query Patterns**:
- Branch-isolated search: `WHERE tags->>'branch' = $1` (uses GIN index)
- Full-text search: `WHERE ts @@ to_tsquery($1)` (uses GIN index)
- Scope proximity: `ORDER BY CASE WHEN tags->>'branch'=$1 THEN 1.0 ... END` (ranking formula)

---

## Next Steps

1. **Phase 1 Complete**: Proceed to Phase 2 (memory.store implementation for section kind)
2. **Migration Execution**: Apply 001→002→003 to dev Postgres 18 instance
3. **Seed Data**: Populate with minimal examples (1 document, 3 sections, 1 ADR, 1 issue)
4. **Validation**: Verify triggers fire correctly (unit tests)
