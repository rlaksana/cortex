# Cortex Memory MCP v1.0.0

Minimal two-tool MCP server with **autonomous collaboration** for Claude Code and AI agents.

## Features

- ✅ **2 Tools**: `memory.store` and `memory.find` (constitutional constraint)
- ✅ **Autonomous Collaboration**: Claude Code decides operations without user prompts
- ✅ **12 Knowledge Types**: 9 typed + 3 graph extension (entity, relation, observation)
- ✅ **Auto-Purge**: Threshold-based cleanup (24h OR 1000 ops)
- ✅ **Delete Operations**: Hard delete with cascade support
- ✅ **Similarity Detection**: Duplicate/contradiction detection for autonomous decisions
- ✅ **Confidence Scoring**: Search results include confidence for autonomous retry logic
- ✅ **Branch Isolation**: Default branch filtering, explicit scope widening
- ✅ **Full Audit Trail**: 100% mutation coverage, immutable audit log
- ✅ **Idempotent Writes**: Content-based deduplication
- ✅ **FTS Search**: PostgreSQL full-text search with pg_trgm
- ✅ **Performance SLOs**: P95 < 300ms on ≤3M sections

## Quick Start

```bash
# Install dependencies
npm install

# Setup database (requires Docker)
docker-compose up -d

# Run migrations
npm run db:migrate

# Seed sample data
npm run db:seed

# Start server
npm run dev
```

## Autonomous Collaboration

Cortex Memory is designed for **autonomous AI agents** (Claude Code, GPT-based CLI tools) that make decisions without user prompts.

### How It Works

**Traditional Memory System** (Bad UX):
```typescript
// System asks user constantly
const similar = await memory.find({query: "auth"});
// ❌ System: "Found 3 similar items. Which one to update?"
// ❌ User: "Ugh, just pick one!"
```

**Autonomous Cortex Memory** (Good UX):
```typescript
// Claude Code decides autonomously
const searchResult = await memory.find({query: "PostgreSQL version"});

if (searchResult.autonomous_metadata.confidence === 'high' && searchResult.hits.length > 0) {
  // Found old version, replace autonomously
  await memory.store({operation: "delete", id: searchResult.hits[0].id});
  const result = await memory.store({kind: "section", data: {title: "Database", body_md: "PostgreSQL 18"}});

  // ✅ Claude: "Updated database version to PostgreSQL 18"
  // ✅ User: Happy, no questions asked!
}
```

### Key Features

**1. Autonomous Context** (memory.store response):
```json
{
  "stored": [{"id": "uuid", "status": "inserted", "kind": "section"}],
  "autonomous_context": {
    "action_performed": "created",
    "duplicates_found": 0,
    "recommendation": "Inform user: Item saved successfully.",
    "user_message_suggestion": "✓ Saved section"
  }
}
```

**2. Confidence Scoring** (memory.find response):
```json
{
  "hits": [...],
  "autonomous_metadata": {
    "confidence": "high",
    "recommendation": "Results sufficient, use top results.",
    "user_message_suggestion": "Found 3 results"
  }
}
```

**3. Auto-Purge** (seamless, zero config):
- Runs every 24 hours OR 1000 operations
- Deletes: closed todos (>90d), merged PRs (>30d), closed issues (>90d)
- Non-blocking (< 1ms overhead)

## Usage

See [specs/001-create-specs-000/quickstart.md](./specs/001-create-specs-000/quickstart.md) for detailed examples.

## Architecture

- **Language**: TypeScript 5.3+, Node.js 20+
- **Database**: PostgreSQL 18+ (pgcrypto, pg_trgm)
- **Transport**: MCP STDIO (JSON-RPC 2.0)
- **Testing**: Vitest (unit + integration + E2E)
- **Validation**: Zod runtime schemas

## Constitutional Principles

1. **Minimal API**: Exactly 2 tools, no more
2. **Single SoT**: PostgreSQL exclusive source
3. **Branch Isolation**: Default read isolation
4. **Immutability**: ADR/spec write-locks
5. **Extensibility**: Server-side routing
6. **Performance**: P95 < 300ms SLO
7. **Type Safety**: Zod + TypeScript

## Configuration

Auto-purge is enabled by default with sensible defaults. Configure via environment variables:

```bash
# .env file
DATABASE_URL=postgresql://cortex:password@localhost:5432/cortex_prod

# Auto-purge configuration (optional)
PURGE_TIME_THRESHOLD_HOURS=24        # Trigger after 24 hours
PURGE_OPERATION_THRESHOLD=1000       # Trigger after 1000 operations
PURGE_ENABLED=true                   # Enable/disable auto-purge

# TTL defaults (used by purge rules)
TODO_TTL_DAYS=90                     # Delete closed todos after 90 days
PR_TTL_DAYS=30                       # Delete merged PRs after 30 days
ISSUE_TTL_DAYS=90                    # Delete closed issues after 90 days
CHANGE_TTL_DAYS=90                   # Delete old changes after 90 days
```

### Purge Status

Check purge status via direct SQL (admin tool coming soon):

```sql
SELECT * FROM _purge_metadata;
```

Returns:
- `last_purge_at`: Last purge timestamp
- `operations_since_purge`: Operations since last purge
- `deleted_counts`: Items deleted in last purge (by type)
- `last_duration_ms`: Duration of last purge

## Development

```bash
npm run lint        # ESLint
npm run typecheck   # TypeScript
npm run test        # Unit tests
npm test:integration # Integration tests (requires DB)
npm run build       # Compile to dist/
```

## License

MIT
