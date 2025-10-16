# Graph Schema Extension Design

**Created**: 2025-10-13
**Status**: Draft
**Task**: T1 - Design graph schema extension
**Purpose**: Add knowledge graph capabilities while preserving constitutional principles

## Overview

This design extends mcp-cortex with knowledge graph capabilities by adding 3 new tables that enable:
- **Flexible entities** (user-defined types beyond 9 fixed types)
- **Explicit relationships** between any knowledge items
- **Fine-grained observations** (append/delete individual facts)

### Design Philosophy

**Hybrid Approach**: Existing 9 knowledge types (section, runbook, change, issue, decision, todo, release_note, ddl, pr_context) remain as "typed entities" in their current tables. New flexible entities are stored in `knowledge_entity` table. All entities (typed and flexible) can participate in relationships via `knowledge_relation`.

## New Tables

### 1. knowledge_entity (Flexible Entity Storage)

**Purpose**: Store user-defined entities with dynamic schemas (10th knowledge type: `entity`)

```typescript
// Drizzle schema
export const knowledge_entity = pgTable('knowledge_entity', {
  id: uuid('id').primaryKey().default(uuidv7),
  entity_type: text('entity_type').notNull(), // user-defined: "user", "organization", "project", etc.
  name: text('name').notNull(),
  data: jsonb('data').notNull(), // flexible schema: { key: value, ... }
  tags: jsonb('tags').notNull().default(sql`'{}'::jsonb`), // scope: {org, project, branch, ...}
  content_hash: text('content_hash').notNull(), // SHA-256(entity_type + name + data) for deduplication
  deleted_at: timestamp('deleted_at', { withTimezone: true }), // soft delete
  created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
  nameIdx: index('knowledge_entity_name_idx').on(table.name),
  typeIdx: index('knowledge_entity_type_idx').on(table.entity_type),
  tagsIdx: index('knowledge_entity_tags_gin').using('gin', table.tags),
  dataIdx: index('knowledge_entity_data_gin').using('gin', table.data),
  contentHashIdx: index('knowledge_entity_content_hash_idx').on(table.content_hash),
  deletedAtIdx: index('knowledge_entity_deleted_at_idx').on(table.deleted_at), // for filtering out soft-deleted
  uniqueActiveEntity: index('knowledge_entity_unique_active').on(table.entity_type, table.name).where(sql`deleted_at IS NULL`), // prevent duplicate active entities
}));
```

**Key Features**:
- `entity_type`: User-defined (e.g., "user", "organization", "goal", "preference")
- `name`: Unique identifier within type (e.g., "default_user", "andal_software")
- `data`: Flexible JSONB schema - no validation constraints
- `content_hash`: Deduplication key (idempotent writes)
- `deleted_at`: Soft delete (preserves audit trail, enables undelete)
- GIN indexes on `data` and `tags` for fast JSON queries

### 2. knowledge_relation (Entity Relationships)

**Purpose**: Store directed relationships between any knowledge items (typed or flexible entities)

```typescript
// Drizzle schema
export const knowledge_relation = pgTable('knowledge_relation', {
  id: uuid('id').primaryKey().default(uuidv7),
  from_entity_type: text('from_entity_type').notNull(), // "section" | "decision" | "entity" | ...
  from_entity_id: uuid('from_entity_id').notNull(),
  to_entity_type: text('to_entity_type').notNull(),
  to_entity_id: uuid('to_entity_id').notNull(),
  relation_type: text('relation_type').notNull(), // "resolves", "supersedes", "references", "implements", "works_at", etc.
  metadata: jsonb('metadata'), // optional: { weight: 1.0, confidence: 0.85, since: "2025-01-01" }
  tags: jsonb('tags').notNull().default(sql`'{}'::jsonb`), // scope: {org, project, branch, ...}
  deleted_at: timestamp('deleted_at', { withTimezone: true }), // soft delete
  created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
  fromIdx: index('knowledge_relation_from_idx').on(table.from_entity_type, table.from_entity_id),
  toIdx: index('knowledge_relation_to_idx').on(table.to_entity_type, table.to_entity_id),
  relationTypeIdx: index('knowledge_relation_type_idx').on(table.relation_type),
  tagsIdx: index('knowledge_relation_tags_gin').using('gin', table.tags),
  metadataIdx: index('knowledge_relation_metadata_gin').using('gin', table.metadata),
  deletedAtIdx: index('knowledge_relation_deleted_at_idx').on(table.deleted_at),
  uniqueActiveRelation: index('knowledge_relation_unique_active').on(
    table.from_entity_type, table.from_entity_id,
    table.to_entity_type, table.to_entity_id,
    table.relation_type
  ).where(sql`deleted_at IS NULL`), // prevent duplicate active relations
}));
```

**Key Features**:
- **Polymorphic relationships**: Links any entity type to any other (section→decision, entity→entity, etc.)
- **Directed edges**: `from` → `to` with explicit `relation_type`
- **Rich metadata**: Optional JSONB for relation attributes (weight, confidence, timestamps)
- **Soft delete**: Preserves relationship history
- Composite unique constraint on active relations (prevents duplicates)

**Common relation_types**:
- `resolves`: decision→issue, change→issue
- `supersedes`: decision→decision (ADR evolution)
- `references`: section→section, change→decision
- `implements`: task→decision, change→decision
- `documents`: session→task, session→decision
- `blocks`: task→task, issue→task
- `depends_on`: task→task
- `works_at`: user→organization (flexible entities)
- `collaborates_with`: user→user
- `has_goal`: user→goal
- `prefers`: user→preference

### 3. knowledge_observation (Fine-Grained Facts)

**Purpose**: Store timestamped observations/facts attached to any entity

```typescript
// Drizzle schema
export const knowledge_observation = pgTable('knowledge_observation', {
  id: uuid('id').primaryKey().default(uuidv7),
  entity_type: text('entity_type').notNull(), // "section" | "decision" | "entity" | ...
  entity_id: uuid('entity_id').notNull(),
  observation: text('observation').notNull(), // key:value format or free text
  observation_type: text('observation_type'), // optional: "status", "progress", "note", "metric"
  metadata: jsonb('metadata'), // optional: { source: "user", confidence: 0.9 }
  deleted_at: timestamp('deleted_at', { withTimezone: true }), // soft delete (not physical delete)
  created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
  entityIdx: index('knowledge_observation_entity_idx').on(table.entity_type, table.entity_id),
  typeIdx: index('knowledge_observation_type_idx').on(table.observation_type),
  metadataIdx: index('knowledge_observation_metadata_gin').using('gin', table.metadata),
  createdAtIdx: index('knowledge_observation_created_at_idx').on(table.created_at),
  deletedAtIdx: index('knowledge_observation_deleted_at_idx').on(table.deleted_at),
  // Full-text search on observations
  observationFtsIdx: index('knowledge_observation_fts_idx').using(
    'gin',
    sql`to_tsvector('english', ${table.observation})`
  ),
}));
```

**Key Features**:
- **Append-only by default**: New observations added without modifying existing
- **Soft delete**: `deleted_at` marks observations as inactive (preserves history)
- **Timestamped**: `created_at` tracks when fact was observed
- **Polymorphic**: Attaches to any entity (typed or flexible)
- **Full-text search**: GIN index on observation text for fast search
- **Typed observations**: Optional `observation_type` for categorization

**Observation formats**:
- Key:value: `"status: in_progress"`, `"progress: 50%"`, `"priority: high"`
- Free text: `"User prefers Python over JavaScript for backend work"`
- Metrics: `"latency_p95: 245ms"`, `"test_coverage: 87%"`

## Entity Mapping Table

To support polymorphic queries across all entity types, we introduce a **unified entity reference**:

| Entity Source | entity_type | entity_id | Table |
|--------------|-------------|-----------|-------|
| Section | `"section"` | UUID | `section` |
| Runbook | `"runbook"` | UUID | `runbook` |
| Change | `"change"` | UUID | `change_log` |
| Issue | `"issue"` | UUID | `issue_log` |
| Decision | `"decision"` | UUID | `adr_decision` |
| Todo | `"todo"` | UUID | `todo_log` |
| Release Note | `"release_note"` | UUID | `release_note` |
| DDL | `"ddl"` | UUID | `ddl_history` |
| PR Context | `"pr_context"` | UUID | `pr_context` |
| **Flexible Entity** | User-defined | UUID | `knowledge_entity` |

## ERD (Entity-Relationship Diagram)

```
┌─────────────────────┐
│  Existing 9 Types   │
│  (section, runbook, │
│   change, issue,    │
│   decision, todo,   │
│   release_note,     │
│   ddl, pr_context)  │
└──────────┬──────────┘
           │ entity_id
           │ entity_type
           ▼
┌─────────────────────────────────────────────────────┐
│          knowledge_relation (NEW)                    │
│  ┌─────────────────────────────────────────────┐   │
│  │ from_entity_type, from_entity_id            │   │
│  │ to_entity_type, to_entity_id                │   │
│  │ relation_type, metadata, tags               │   │
│  │ deleted_at, created_at, updated_at          │   │
│  └─────────────────────────────────────────────┘   │
└──────────┬─────────────────────────────┬────────────┘
           │                             │
           │ to_entity_id                │ from_entity_id
           │ to_entity_type              │ from_entity_type
           ▼                             ▼
┌─────────────────────────┐    ┌─────────────────────────┐
│  knowledge_entity (NEW) │    │  knowledge_observation  │
│  ┌───────────────────┐  │    │        (NEW)            │
│  │ entity_type, name │  │    │  ┌───────────────────┐  │
│  │ data (JSONB)      │  │◄───┤  │ entity_type       │  │
│  │ tags, content_hash│  │    │  │ entity_id         │  │
│  │ deleted_at        │  │    │  │ observation       │  │
│  │ created_at        │  │    │  │ observation_type  │  │
│  └───────────────────┘  │    │  │ metadata, deleted_at│
└─────────────────────────┘    │  └───────────────────┘  │
                                └─────────────────────────┘
```

**Key Relationships**:
1. **Any entity → knowledge_relation (from)**: Entities can be the source of relationships
2. **Any entity → knowledge_relation (to)**: Entities can be the target of relationships
3. **Any entity → knowledge_observation**: Entities can have observations attached

## Migration Strategy

### Phase 1: Add New Tables (Non-Breaking)

```sql
-- Migration 004_add_graph_schema.sql

-- 1. Create knowledge_entity table
CREATE TABLE knowledge_entity (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_type TEXT NOT NULL,
  name TEXT NOT NULL,
  data JSONB NOT NULL,
  tags JSONB NOT NULL DEFAULT '{}'::jsonb,
  content_hash TEXT NOT NULL,
  deleted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX knowledge_entity_name_idx ON knowledge_entity(name);
CREATE INDEX knowledge_entity_type_idx ON knowledge_entity(entity_type);
CREATE INDEX knowledge_entity_tags_gin ON knowledge_entity USING gin(tags);
CREATE INDEX knowledge_entity_data_gin ON knowledge_entity USING gin(data);
CREATE INDEX knowledge_entity_content_hash_idx ON knowledge_entity(content_hash);
CREATE INDEX knowledge_entity_deleted_at_idx ON knowledge_entity(deleted_at);
CREATE UNIQUE INDEX knowledge_entity_unique_active ON knowledge_entity(entity_type, name) WHERE deleted_at IS NULL;

-- 2. Create knowledge_relation table
CREATE TABLE knowledge_relation (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  from_entity_type TEXT NOT NULL,
  from_entity_id UUID NOT NULL,
  to_entity_type TEXT NOT NULL,
  to_entity_id UUID NOT NULL,
  relation_type TEXT NOT NULL,
  metadata JSONB,
  tags JSONB NOT NULL DEFAULT '{}'::jsonb,
  deleted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX knowledge_relation_from_idx ON knowledge_relation(from_entity_type, from_entity_id);
CREATE INDEX knowledge_relation_to_idx ON knowledge_relation(to_entity_type, to_entity_id);
CREATE INDEX knowledge_relation_type_idx ON knowledge_relation(relation_type);
CREATE INDEX knowledge_relation_tags_gin ON knowledge_relation USING gin(tags);
CREATE INDEX knowledge_relation_metadata_gin ON knowledge_relation USING gin(metadata);
CREATE INDEX knowledge_relation_deleted_at_idx ON knowledge_relation(deleted_at);
CREATE UNIQUE INDEX knowledge_relation_unique_active ON knowledge_relation(
  from_entity_type, from_entity_id, to_entity_type, to_entity_id, relation_type
) WHERE deleted_at IS NULL;

-- 3. Create knowledge_observation table
CREATE TABLE knowledge_observation (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_type TEXT NOT NULL,
  entity_id UUID NOT NULL,
  observation TEXT NOT NULL,
  observation_type TEXT,
  metadata JSONB,
  deleted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX knowledge_observation_entity_idx ON knowledge_observation(entity_type, entity_id);
CREATE INDEX knowledge_observation_type_idx ON knowledge_observation(observation_type);
CREATE INDEX knowledge_observation_metadata_gin ON knowledge_observation USING gin(metadata);
CREATE INDEX knowledge_observation_created_at_idx ON knowledge_observation(created_at);
CREATE INDEX knowledge_observation_deleted_at_idx ON knowledge_observation(deleted_at);
CREATE INDEX knowledge_observation_fts_idx ON knowledge_observation USING gin(to_tsvector('english', observation));

-- 4. Add triggers for updated_at timestamps
CREATE OR REPLACE FUNCTION touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER knowledge_entity_touch_updated_at
  BEFORE UPDATE ON knowledge_entity
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE TRIGGER knowledge_relation_touch_updated_at
  BEFORE UPDATE ON knowledge_relation
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- 5. Add audit triggers (extend event_audit to cover new tables)
CREATE OR REPLACE FUNCTION audit_mutation()
RETURNS TRIGGER AS $$
BEGIN
  IF (TG_OP = 'DELETE') THEN
    INSERT INTO event_audit (entity_type, entity_id, operation, change_summary)
    VALUES (TG_TABLE_NAME, OLD.id, 'DELETE', row_to_json(OLD)::jsonb);
    RETURN OLD;
  ELSIF (TG_OP = 'UPDATE') THEN
    INSERT INTO event_audit (entity_type, entity_id, operation, change_summary)
    VALUES (TG_TABLE_NAME, NEW.id, 'UPDATE', jsonb_build_object('old', row_to_json(OLD)::jsonb, 'new', row_to_json(NEW)::jsonb));
    RETURN NEW;
  ELSIF (TG_OP = 'INSERT') THEN
    INSERT INTO event_audit (entity_type, entity_id, operation, change_summary)
    VALUES (TG_TABLE_NAME, NEW.id, 'INSERT', row_to_json(NEW)::jsonb);
    RETURN NEW;
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER knowledge_entity_audit AFTER INSERT OR UPDATE OR DELETE ON knowledge_entity
  FOR EACH ROW EXECUTE FUNCTION audit_mutation();

CREATE TRIGGER knowledge_relation_audit AFTER INSERT OR UPDATE OR DELETE ON knowledge_relation
  FOR EACH ROW EXECUTE FUNCTION audit_mutation();

CREATE TRIGGER knowledge_observation_audit AFTER INSERT OR UPDATE OR DELETE ON knowledge_observation
  FOR EACH ROW EXECUTE FUNCTION audit_mutation();

COMMENT ON TABLE knowledge_entity IS 'Flexible entity storage for user-defined types (10th knowledge type)';
COMMENT ON TABLE knowledge_relation IS 'Directed relationships between any knowledge items';
COMMENT ON TABLE knowledge_observation IS 'Fine-grained timestamped facts attached to entities';
```

### Phase 2: Backfill Existing Relations (Optional)

If desired, extract implicit relations from existing data:

```sql
-- Extract "supersedes" relations from adr_decision
INSERT INTO knowledge_relation (from_entity_type, from_entity_id, to_entity_type, to_entity_id, relation_type, tags)
SELECT 'decision', id, 'decision', supersedes, 'supersedes', tags
FROM adr_decision
WHERE supersedes IS NOT NULL;

-- Extract "references" from change_log to issues (parse commit messages for issue IDs)
-- (Would require custom logic based on commit message format)
```

## Backward Compatibility

**Guarantee**: All existing functionality continues to work without changes.

- Existing 9 knowledge types remain in their current tables
- `memory.store` and `memory.find` continue to work for existing types
- No schema changes to existing tables (11 tables remain untouched)
- New graph capabilities are **additive** via new tables

**Migration Risk**: **LOW** - New tables are isolated, no foreign key constraints to existing tables.

## API Extension Design (Preview for T2-T6)

### memory.store (Extended)

```typescript
// Existing: Store knowledge items
memory.store({ items: [{ kind: "section", data: {...}, scope: {...} }] })

// NEW: Store flexible entity
memory.store({ items: [{ kind: "entity", data: { entity_type: "user", name: "default_user", data: {...} }, scope: {...} }] })

// NEW: Store relation
memory.store({ items: [{ kind: "relation", data: { from_type: "decision", from_id: "uuid-123", to_type: "issue", to_id: "uuid-456", relation_type: "resolves" }, scope: {...} }] })

// NEW: Add observation
memory.store({ items: [{ kind: "observation", data: { entity_type: "task", entity_id: "uuid-789", observation: "status: completed", observation_type: "status" }, scope: {...} }] })

// NEW: Delete (soft delete)
memory.store({ items: [{ kind: "entity", operation: "delete", id: "uuid-to-delete", scope: {...} }] })
```

### memory.find (Extended)

```typescript
// Existing: FTS search
memory.find({ query: "authentication bug", mode: "fast" })

// NEW: Graph traversal
memory.find({
  query: "decision:uuid-123",
  traverse: {
    depth: 2,
    relation_types: ["resolves", "supersedes"]
  }
})
// Returns: decision + all issues it resolves + superseding decisions

// NEW: Entity-specific search
memory.find({ query: "user", types: ["entity"], entity_type_filter: "user" })
```

## Performance Considerations

### Index Strategy

1. **GIN indexes** on JSONB fields (`data`, `tags`, `metadata`) for fast JSON queries
2. **B-tree indexes** on frequently queried columns (`entity_type`, `name`, `relation_type`)
3. **Composite indexes** for common query patterns (e.g., `from_entity_type + from_entity_id`)
4. **Partial indexes** for soft delete filtering (`WHERE deleted_at IS NULL`)
5. **FTS index** on observations for full-text search

### Query Patterns

**Graph Traversal** (Recursive CTE):
```sql
WITH RECURSIVE graph_traverse AS (
  -- Base case: start node
  SELECT 'decision' as entity_type, id as entity_id, 0 as depth
  FROM adr_decision WHERE id = $1

  UNION ALL

  -- Recursive case: follow relations
  SELECT kr.to_entity_type, kr.to_entity_id, gt.depth + 1
  FROM graph_traverse gt
  JOIN knowledge_relation kr ON
    kr.from_entity_type = gt.entity_type AND
    kr.from_entity_id = gt.entity_id
  WHERE gt.depth < $2 AND kr.deleted_at IS NULL
)
SELECT * FROM graph_traverse;
```

**Expected Performance**:
- Single-hop traversal: <10ms
- 2-hop traversal: <50ms
- 3-hop traversal: <150ms (within P95 < 300ms SLO)

### Storage Estimates

Assuming 1M knowledge items + graph:
- `knowledge_entity`: ~100K entities × 2KB avg = 200MB
- `knowledge_relation`: ~500K relations × 256B avg = 128MB
- `knowledge_observation`: ~1M observations × 512B avg = 512MB
- **Total additional storage**: ~850MB (acceptable growth)

## Constitutional Compliance

### Principle I: Minimal API Surface ✅
- **Maintained**: Still 2 tools (`memory.store`, `memory.find`)
- **Extended**: New parameters and `kind` values, not new tools

### Principle II: Single Source of Truth ✅
- **Maintained**: PostgreSQL remains exclusive source
- **Enhanced**: Graph data also in PostgreSQL (not external Neo4j/Qdrant)

### Principle III: Branch Isolation by Default ✅
- **Maintained**: `tags` field on all new tables for scope filtering
- **Enhanced**: Relations and observations inherit scope from entities

### Principle IV: Immutable Content Integrity ✅
- **Maintained**: Soft delete preserves history
- **Enhanced**: Audit trail covers all graph mutations

### Principle V: Extensibility Without API Breakage ✅
- **Maintained**: Existing API unchanged
- **Enhanced**: New capabilities via parameter extensions

### Principle VI: Performance Discipline ✅
- **Maintained**: Graph traversal within P95 < 300ms SLO
- **Measured**: Performance tests in T8

### Principle VII: Type Safety & Schema Validation ✅
- **Maintained**: Zod validation for all new kinds
- **Relaxed**: `entity` kind allows flexible schema (intentional trade-off)

## Next Steps

1. **T2**: Implement flexible entity type (Zod schema + storage handler)
2. **T3**: Implement relation storage (Zod schema + storage handler)
3. **T4**: Implement graph traversal (recursive CTE queries)
4. **T5**: Implement observation management (append/delete operations)
5. **T6**: Implement delete operations (soft delete logic)
6. **T7**: Update documentation
7. **T8**: Comprehensive testing

---

**Design Status**: ✅ Ready for implementation
**Risk Level**: LOW (additive changes, no breaking modifications)
**Estimated Migration Time**: <5 minutes (run SQL migration)
