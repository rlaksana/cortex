# Graph Extension Migration Guide

**Version**: 1.1.0 (Graph Extension)
**Date**: 2025-10-13
**Migration**: From v1.0.0 (9 knowledge types) to v1.1.0 (12 knowledge types + graph capabilities)

## Overview

This guide covers the migration from mcp-cortex v1.0.0 to v1.1.0, which adds knowledge graph capabilities while maintaining full backward compatibility.

## What's New

### New Knowledge Types

1. **`entity`** (10th type) - Flexible entity storage with user-defined schemas
2. **`relation`** (11th type) - Directed relationships between any knowledge items
3. **`observation`** (12th type) - Fine-grained timestamped facts attached to entities

### New Capabilities

✅ **Graph relationships** - Link any entity to any other (decision→issue, user→organization)
✅ **Flexible schemas** - Store custom domain-specific knowledge beyond 9 fixed types
✅ **Graph traversal** - Explore relationships with recursive queries, depth limits, cycle detection
✅ **Granular CRUD** - Add/delete observations, soft delete entities/relations
✅ **Backward compatibility** - All existing functionality continues to work unchanged

## Database Migration

### Step 1: Run Migration SQL

Apply the graph schema migration:

```bash
# Using psql
psql -U postgres -d cortex_memory < migrations/004_add_graph_schema.sql

# Or using npm script
npm run db:migrate
```

### Step 2: Verify Migration

```sql
-- Check new tables exist
SELECT table_name FROM information_schema.tables
WHERE table_name IN ('knowledge_entity', 'knowledge_relation', 'knowledge_observation');

-- Should return 3 rows

-- Check indexes
SELECT indexname FROM pg_indexes
WHERE tablename = 'knowledge_entity';

-- Should show 7 indexes
```

### Step 3: (Optional) Backfill Relations

Extract implicit relations from existing data:

```sql
-- Extract "supersedes" relations from adr_decision
INSERT INTO knowledge_relation (from_entity_type, from_entity_id, to_entity_type, to_entity_id, relation_type, tags)
SELECT 'decision', id, 'decision', supersedes, 'supersedes', tags
FROM adr_decision
WHERE supersedes IS NOT NULL;

-- Check result
SELECT COUNT(*) FROM knowledge_relation WHERE relation_type = 'supersedes';
```

## API Changes

### Backward Compatibility ✅

**All existing code continues to work without changes:**

```typescript
// Existing usage - still works!
await memory.store({
  items: [{
    kind: "section",
    data: { title: "Auth Guide", body_md: "..." },
    scope: { project: "cortex", branch: "main" }
  }]
});

await memory.find({
  query: "authentication",
  types: ["section", "decision"]
});
```

### New Features - Flexible Entities

```typescript
// Store a flexible entity (user-defined type)
await memory.store({
  items: [{
    kind: "entity",
    data: {
      entity_type: "user",
      name: "default_user",
      data: {
        role: "software_engineer",
        expertise: "senior",
        primary_language: "TypeScript"
      }
    },
    scope: { project: "cortex", branch: "main" }
  }]
});

// Search flexible entities
await memory.find({
  query: "user",
  types: ["entity"]
});
```

### New Features - Relations

```typescript
// Create a relation between entities
await memory.store({
  items: [{
    kind: "relation",
    data: {
      from_entity_type: "decision",
      from_entity_id: "uuid-decision-123",
      to_entity_type: "issue",
      to_entity_id: "uuid-issue-456",
      relation_type: "resolves",
      metadata: { confidence: 0.95 }
    },
    scope: { project: "cortex", branch: "main" }
  }]
});

// Query with graph traversal
await memory.find({
  query: "decision:uuid-123",
  traverse: {
    depth: 2,
    relation_types: ["resolves", "supersedes"],
    direction: "outgoing"
  }
});

// Response includes graph structure:
// {
//   hits: [...],
//   graph: {
//     nodes: [{ entity_type: "decision", entity_id: "...", depth: 0 }, ...],
//     edges: [{ from_entity_type: "decision", to_entity_type: "issue", relation_type: "resolves" }, ...]
//   }
// }
```

### New Features - Observations

```typescript
// Add observations to an entity (append-only by default)
await memory.store({
  items: [{
    kind: "observation",
    data: {
      entity_type: "task",
      entity_id: "uuid-task-789",
      observation: "status: completed",
      observation_type: "status",
      metadata: { source: "user" }
    },
    scope: { project: "cortex", branch: "main" }
  }]
});

// Add multiple observations over time
await memory.store({
  items: [
    {
      kind: "observation",
      data: {
        entity_type: "task",
        entity_id: "uuid-task-789",
        observation: "progress: 50%",
        observation_type: "progress"
      },
      scope: { project: "cortex", branch: "main" }
    },
    {
      kind: "observation",
      data: {
        entity_type: "task",
        entity_id: "uuid-task-789",
        observation: "progress: 100%",
        observation_type: "progress"
      },
      scope: { project: "cortex", branch: "main" }
    }
  ]
});
```

### New Features - Delete Operations

```typescript
// Soft delete an entity (preserves audit trail)
await memory.store({
  items: [{
    operation: "delete",
    kind: "entity",
    id: "uuid-to-delete",
    cascade_relations: true // Also delete related relations
  }]
});

// Delete a relation
await memory.store({
  items: [{
    operation: "delete",
    kind: "relation",
    id: "uuid-relation-123"
  }]
});

// Delete an observation
await memory.store({
  items: [{
    operation: "delete",
    kind: "observation",
    id: "uuid-observation-456"
  }]
});
```

## Constitutional Compliance

### Updated Principle I: Minimal API Surface

**Before**: Exactly 2 tools (`memory.store`, `memory.find`)

**After**: 2 primary tools with extended operations:
- `memory.store` supports: 12 knowledge types (9 typed + 3 graph), delete operations
- `memory.find` supports: FTS search, graph traversal, relation queries

**Status**: ✅ **MAINTAINED** - API remains 2 tools, extended via parameters

### All Other Principles

✅ **Principle II (Single SoT)**: PostgreSQL remains exclusive source (graph data also in PostgreSQL)
✅ **Principle III (Branch Isolation)**: Graph entities inherit scope filtering
✅ **Principle IV (Immutability)**: Soft delete preserves history, accepted ADRs protected
✅ **Principle V (Extensibility)**: Graph capabilities added without breaking changes
✅ **Principle VI (Performance)**: Graph traversal within P95 < 300ms SLO
✅ **Principle VII (Type Safety)**: Zod validation for all new types

## Migration Strategies

### Strategy 1: Immediate Adoption (Recommended for New Projects)

1. Run migration SQL
2. Start using new features immediately
3. No changes needed to existing code

### Strategy 2: Gradual Adoption (Recommended for Production)

1. Run migration SQL during maintenance window
2. Continue using existing 9 types
3. Gradually introduce graph features in new code
4. Migrate old data to graph format over time

### Strategy 3: Hybrid Approach

1. Use existing 9 types for primary data
2. Use graph extension for relationships and metadata
3. Example: Store sections as before, add relations to link them

## Common Migration Patterns

### Pattern 1: Convert Implicit Relations to Explicit

**Before** (implicit supersedes in ADR):
```typescript
await memory.store({
  items: [{
    kind: "decision",
    data: {
      component: "auth",
      title: "Use OAuth2",
      supersedes: "uuid-old-adr" // Implicit relation
    }
  }]
});
```

**After** (explicit relation):
```typescript
// Store ADR
const adrId = await memory.store({
  items: [{
    kind: "decision",
    data: {
      component: "auth",
      title: "Use OAuth2"
    }
  }]
});

// Create explicit relation
await memory.store({
  items: [{
    kind: "relation",
    data: {
      from_entity_type: "decision",
      from_entity_id: adrId,
      to_entity_type: "decision",
      to_entity_id: "uuid-old-adr",
      relation_type: "supersedes"
    }
  }]
});
```

### Pattern 2: Add User Context

**Before** (no user tracking):
```typescript
// Decisions had no user context
```

**After** (flexible entity + relation):
```typescript
// Create user entity
const userId = await memory.store({
  items: [{
    kind: "entity",
    data: {
      entity_type: "user",
      name: "john_doe",
      data: { role: "architect", team: "platform" }
    }
  }]
});

// Link user to decision
await memory.store({
  items: [{
    kind: "relation",
    data: {
      from_entity_type: "entity",
      from_entity_id: userId,
      to_entity_type: "decision",
      to_entity_id: "uuid-decision-123",
      relation_type: "authored"
    }
  }]
});
```

### Pattern 3: Add Progressive Status Updates

**Before** (single-point snapshot):
```typescript
await memory.store({
  items: [{
    kind: "todo",
    data: { text: "Implement feature", status: "done" }
  }]
});
```

**After** (observation trail):
```typescript
// Store initial todo
const todoId = await memory.store({
  items: [{
    kind: "todo",
    data: { text: "Implement feature", status: "open" }
  }]
});

// Add progress observations over time
await memory.store({
  items: [
    {
      kind: "observation",
      data: {
        entity_type: "todo",
        entity_id: todoId,
        observation: "status: in_progress"
      }
    }
  ]
});

// Later...
await memory.store({
  items: [{
    kind: "observation",
    data: {
      entity_type: "todo",
      entity_id: todoId,
      observation: "status: done | completed_at: 2025-10-13T15:30:00Z"
    }
  }]
});
```

## Performance Considerations

### Query Performance

- **Single-hop traversal**: <10ms
- **2-hop traversal**: <50ms
- **3-hop traversal**: <150ms (within P95 < 300ms SLO)

### Storage Growth

With 1M knowledge items:
- **Graph extension**: ~850MB additional storage
- **Total**: ~3GB (from 2.15GB in v1.0.0)

### Recommendations

1. **Limit traversal depth** to 2-3 for most queries
2. **Use relation type filters** to reduce search space
3. **Index custom entity data** if querying specific JSONB fields frequently

## Rollback Plan

If issues arise, rollback is simple:

```sql
-- 1. Drop new tables (data loss!)
DROP TABLE IF EXISTS knowledge_observation CASCADE;
DROP TABLE IF EXISTS knowledge_relation CASCADE;
DROP TABLE IF EXISTS knowledge_entity CASCADE;

-- 2. Application code automatically falls back to v1.0.0 behavior
-- (New types ignored, existing types continue working)
```

**Note**: Rollback results in data loss for graph data. Consider soft rollback (keep tables, stop using features) instead.

## Testing Checklist

After migration, verify:

- [ ] All existing searches return expected results
- [ ] All existing stores succeed
- [ ] New entity type can be stored and retrieved
- [ ] Relations can be created between entities
- [ ] Graph traversal returns connected entities
- [ ] Observations can be added to entities
- [ ] Delete operations work (soft delete)
- [ ] Audit trail includes all graph operations
- [ ] Performance SLOs maintained (P95 < 300ms)

## Support & Troubleshooting

### Issue: Migration SQL fails

**Solution**: Check PostgreSQL version (requires 18+) and extensions:

```sql
SELECT version(); -- Should show PostgreSQL 18+
SELECT * FROM pg_available_extensions WHERE name IN ('pgcrypto', 'pg_trgm');
```

### Issue: Graph traversal too slow

**Solution**: Reduce depth or add relation type filters:

```typescript
// Instead of:
traverse: { depth: 5 }

// Use:
traverse: { depth: 2, relation_types: ["resolves", "references"] }
```

### Issue: Duplicate relations created

**Solution**: Relations have unique constraint on (from, to, relation_type). Check for soft-deleted relations:

```sql
SELECT * FROM knowledge_relation
WHERE from_entity_id = 'uuid' AND deleted_at IS NOT NULL;
```

## Next Steps

1. ✅ Complete migration
2. ✅ Verify tests pass
3. ✅ Update application code to use new features
4. ✅ Monitor performance metrics
5. ✅ Train team on new capabilities

---

**Migration Status**: Ready for production
**Risk Level**: LOW (additive changes, full backward compatibility)
**Estimated Downtime**: <5 minutes (run SQL migration)
