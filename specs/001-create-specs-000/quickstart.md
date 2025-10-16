# Cortex Memory MCP - Quickstart Guide

**Version**: 1.0.0
**Target Audience**: Developers setting up the MCP server locally
**Prerequisites**: Docker, Node.js 20+, git

---

## Overview

This guide walks through local setup, database initialization, and example MCP calls for the Cortex Memory v1 server.

**What you'll do**:
1. Spin up PostgreSQL 18 with required extensions
2. Run database migrations
3. Start the MCP server in STDIO mode
4. Execute example `memory.store` and `memory.find` calls
5. Validate performance with sample dataset

---

## 1. Prerequisites

### System Requirements

- **Node.js**: 20.x or higher
- **Docker**: 24.x or higher (for PostgreSQL 18)
- **Git**: For cloning the repository
- **RAM**: 2GB+ available for PostgreSQL container
- **Disk**: 1GB+ for database and dependencies

### Verify Installations

```bash
node --version   # Should output v20.x.x or higher
docker --version # Should output Docker version 24.x.x or higher
```

---

## 2. Database Setup (Docker Compose)

### docker-compose.yml

Create `docker-compose.yml` in project root:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:18-alpine
    container_name: cortex-postgres
    environment:
      POSTGRES_DB: cortex_dev
      POSTGRES_USER: cortex
      POSTGRES_PASSWORD: cortex_dev_password
      POSTGRES_HOST_AUTH_METHOD: scram-sha-256
    ports:
      - "5432:5432"
    volumes:
      - cortex_data:/var/lib/postgresql/data
      - ./scripts/init-extensions.sql:/docker-entrypoint-initdb.d/01-extensions.sql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U cortex -d cortex_dev"]
      interval: 5s
      timeout: 3s
      retries: 5
    networks:
      - cortex_network

volumes:
  cortex_data:
    driver: local

networks:
  cortex_network:
    driver: bridge
```

### scripts/init-extensions.sql

Create `scripts/init-extensions.sql`:

```sql
-- Enable required PostgreSQL extensions
-- Constitutional Requirement: FR-045, FR-046

\c cortex_dev;

-- pgcrypto: SHA-256 hashing, UUID v7 generation
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- pg_trgm: Trigram similarity for "deep" search mode
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Verify installations
SELECT extname, extversion FROM pg_extension WHERE extname IN ('pgcrypto', 'pg_trgm');
```

### Start PostgreSQL

```bash
docker-compose up -d
docker-compose logs -f postgres  # Watch for "database system is ready to accept connections"
```

**Validation**:
```bash
docker exec -it cortex-postgres psql -U cortex -d cortex_dev -c "SELECT extname FROM pg_extension;"
```

Expected output:
```
 extname
----------
 plpgsql
 pgcrypto
 pg_trgm
(3 rows)
```

---

## 3. Environment Configuration

### .env

Create `.env` file in project root:

```bash
# Database Connection
DATABASE_URL=postgresql://cortex:cortex_dev_password@localhost:5432/cortex_dev

# Logging
LOG_LEVEL=info
NODE_ENV=development

# MCP Server
MCP_TRANSPORT=stdio

# Scope Inference (optional, falls back to git)
CORTEX_ORG=my-org
CORTEX_PROJECT=cortex-memory
CORTEX_BRANCH=main

# Performance Tuning
DB_POOL_MIN=2
DB_POOL_MAX=10
DB_IDLE_TIMEOUT_MS=30000
```

**Security Note**: Never commit `.env` to version control. Add to `.gitignore`.

---

## 4. Install Dependencies

```bash
npm install
```

**Expected output**:
```
added 52 packages in 3s
```

**Key dependencies** (see package.json):
- `@modelcontextprotocol/sdk` - MCP STDIO transport
- `zod` - Runtime schema validation
- `pg`, `node-pg-pool` - PostgreSQL client
- `pino` - Structured logging
- `drizzle-kit` - Database migrations
- `vitest` - Testing framework

---

## 5. Database Migrations

### Generate Migrations (Drizzle Kit)

```bash
npm run db:generate
```

Expected output:
```
✔ Generated migrations successfully!
📦 migrations/0001_initial_schema.sql
📦 migrations/0002_indexes.sql
📦 migrations/0003_triggers.sql
```

### Apply Migrations

```bash
npm run db:migrate
```

Expected output:
```
✅ Applied 3 migrations
   - 0001_initial_schema.sql (11 tables created)
   - 0002_indexes.sql (9 indexes created)
   - 0003_triggers.sql (22 triggers created)
```

### Verify Schema

```bash
docker exec -it cortex-postgres psql -U cortex -d cortex_dev -c "\dt"
```

Expected output:
```
              List of relations
 Schema |      Name       | Type  | Owner
--------+-----------------+-------+--------
 public | document        | table | cortex
 public | section         | table | cortex
 public | runbook         | table | cortex
 public | pr_context      | table | cortex
 public | ddl_history     | table | cortex
 public | release_note    | table | cortex
 public | change_log      | table | cortex
 public | issue_log       | table | cortex
 public | adr_decision    | table | cortex
 public | todo_log        | table | cortex
 public | event_audit     | table | cortex
(11 rows)
```

---

## 6. Seed Sample Data (Optional)

Load minimal examples for testing:

```bash
npm run db:seed
```

This creates:
- 1 document ("Getting Started Guide")
- 3 sections (chunked from document)
- 1 ADR ("Use PostgreSQL 18 for SoT")
- 1 issue ("Setup CI pipeline")
- 1 todo ("Write E2E tests")

**Validation**:
```bash
docker exec -it cortex-postgres psql -U cortex -d cortex_dev -c "SELECT kind, COUNT(*) FROM (
  SELECT 'section' AS kind FROM section
  UNION ALL SELECT 'decision' FROM adr_decision
  UNION ALL SELECT 'issue' FROM issue_log
  UNION ALL SELECT 'todo' FROM todo_log
) counts GROUP BY kind;"
```

Expected output:
```
   kind    | count
-----------+-------
 decision  |     1
 issue     |     1
 section   |     3
 todo      |     1
(4 rows)
```

---

## 7. Start MCP Server

### Development Mode (with hot reload)

```bash
npm run dev
```

Expected output:
```json
{"level":"info","time":"2025-10-09T14:30:00.000Z","service":"cortex-mcp","msg":"Server started in STDIO mode"}
{"level":"info","time":"2025-10-09T14:30:00.001Z","msg":"Database connection pool ready (min=2, max=10)"}
{"level":"info","time":"2025-10-09T14:30:00.002Z","msg":"Registered tools: memory.find, memory.store"}
```

### Production Mode

```bash
npm run build
npm start
```

---

## 8. Example MCP Calls

The MCP server uses JSON-RPC 2.0 over STDIO. Below are example calls you can send via MCP client (e.g., Claude Code).

### Example 1: Store a Section

**Request** (JSON-RPC):
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "memory.store",
    "arguments": {
      "items": [
        {
          "kind": "section",
          "scope": {
            "project": "cortex-memory",
            "branch": "main"
          },
          "data": {
            "title": "Authentication Flow",
            "body_md": "# Authentication Flow\\n\\nOur system uses JWT tokens with RS256 signing. Access tokens expire after 15 minutes, refresh tokens after 7 days.",
            "document_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
          },
          "tags": {
            "category": "architecture",
            "component": "auth"
          }
        }
      ]
    }
  }
}
```

**Response**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "stored": [
      {
        "id": "018c2f3e-4b5a-7890-bcde-f12345678901",
        "status": "inserted",
        "kind": "section",
        "created_at": "2025-10-09T14:30:05.123Z"
      }
    ],
    "errors": []
  }
}
```

### Example 2: Store an ADR (Architecture Decision Record)

**Request**:
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "memory.store",
    "arguments": {
      "items": [
        {
          "kind": "decision",
          "scope": {
            "project": "cortex-memory",
            "branch": "main"
          },
          "data": {
            "component": "database",
            "status": "accepted",
            "title": "Use Drizzle Kit for Migrations",
            "rationale": "Provides type safety, generates TypeScript types from schema, and supports both push (dev) and migrate (prod) workflows.",
            "alternatives_considered": [
              "node-pg-migrate: Pure SQL, more control but no type generation",
              "Kysely: Type-safe queries but requires separate migration tool"
            ],
            "consequences": "Team must learn Drizzle schema syntax. Migration rollback requires manual SQL."
          },
          "tags": {
            "category": "tooling"
          }
        }
      ]
    }
  }
}
```

**Response**:
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "stored": [
      {
        "id": "018c2f3f-8c9d-7123-abcd-ef4567890abc",
        "status": "inserted",
        "kind": "decision",
        "created_at": "2025-10-09T14:31:10.456Z"
      }
    ],
    "errors": []
  }
}
```

### Example 3: Search with Branch Isolation (Fast Mode)

**Request**:
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "memory.find",
    "arguments": {
      "query": "authentication JWT tokens",
      "scope": {
        "project": "cortex-memory",
        "branch": "main"
      },
      "mode": "fast",
      "top_k": 5
    }
  }
}
```

**Response**:
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "hits": [
      {
        "kind": "section",
        "id": "018c2f3e-4b5a-7890-bcde-f12345678901",
        "title": "Authentication Flow",
        "snippet": "...Our system uses **JWT tokens** with RS256 signing. Access tokens expire after 15 minutes...",
        "score": 0.87,
        "scope": {
          "project": "cortex-memory",
          "branch": "main"
        },
        "updated_at": "2025-10-09T14:30:05.123Z",
        "route_used": "fts",
        "confidence": 0.92
      }
    ],
    "suggestions": [],
    "debug": {
      "query_duration_ms": 23,
      "total_candidates": 3,
      "filters_applied": ["scope_branch=main", "fts"]
    }
  }
}
```

### Example 4: Cross-Branch Search (Auto Mode)

**Request**:
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "memory.find",
    "arguments": {
      "query": "migration strategy",
      "scope": {
        "project": "cortex-memory"
      },
      "types": ["decision"],
      "mode": "auto",
      "top_k": 3
    }
  }
}
```

**Response** (finds ADRs from all branches in project):
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "hits": [
      {
        "kind": "decision",
        "id": "018c2f3f-8c9d-7123-abcd-ef4567890abc",
        "title": "Use Drizzle Kit for Migrations",
        "snippet": "...Provides type safety, generates TypeScript types from schema, and supports both push (dev) and **migrate** (prod) workflows...",
        "score": 0.91,
        "scope": {
          "project": "cortex-memory",
          "branch": "main"
        },
        "updated_at": "2025-10-09T14:31:10.456Z",
        "route_used": "fts",
        "confidence": 0.95
      }
    ],
    "suggestions": [],
    "debug": {
      "query_duration_ms": 18,
      "total_candidates": 1,
      "filters_applied": ["scope_project=cortex-memory", "type=decision", "fts"]
    }
  }
}
```

---

## 9. Performance Validation

### Load Test with k6 (100K sections)

```bash
npm run perf:generate -- --count=100000  # Generate synthetic dataset
npm run perf:test                         # Run k6 load test
```

**Expected SLO Compliance** (from FR-049):
- **P95 latency**: < 300ms for `memory.find` queries
- **Throughput**: > 50 queries/second (single instance)
- **Top-3 relevance**: ≥ 80% (sampled evaluation)

**Sample k6 Output**:
```
     ✓ status is 200
     ✓ has hits array
     ✓ p95 latency < 300ms

     checks.........................: 100.00% ✓ 1500      ✗ 0
     http_req_duration..............: avg=142ms   min=45ms   med=125ms   max=289ms   p(95)=267ms
     http_reqs......................: 500     50/s
```

---

## 10. Cleanup

### Stop Services

```bash
docker-compose down
```

### Remove Volumes (reset database)

```bash
docker-compose down -v
```

### Remove Node Modules

```bash
rm -rf node_modules
```

---

## Troubleshooting

### Issue: "Extension pgcrypto does not exist"

**Solution**: Run init script manually:
```bash
docker exec -it cortex-postgres psql -U cortex -d cortex_dev -f /docker-entrypoint-initdb.d/01-extensions.sql
```

### Issue: "Database connection timeout"

**Solution**: Check PostgreSQL health:
```bash
docker-compose ps
docker-compose logs postgres
```

Ensure port 5432 is not already in use:
```bash
lsof -i :5432  # macOS/Linux
netstat -ano | findstr :5432  # Windows
```

### Issue: "Zod validation error on memory.store"

**Solution**: Check input schema against `contracts/knowledge-types.ts`. Common issues:
- Missing required fields (`title`, `body_md`/`body_text` for sections)
- Invalid enum values (e.g., `status` for decisions must be one of: proposed, accepted, rejected, deprecated, superseded)
- Scope missing `project` or `branch`

### Issue: "Slow query performance"

**Solution**: Verify indexes exist:
```bash
docker exec -it cortex-postgres psql -U cortex -d cortex_dev -c "\di"
```

Check for missing GIN indexes on `section.ts` (full-text search) and `section.tags` (scope filtering).

---

## Next Steps

1. **Read the Spec**: [spec.md](./spec.md) for full requirements
2. **Review Architecture**: [plan.md](./plan.md) for 8-phase implementation roadmap
3. **Explore Contracts**: [contracts/](./contracts/) for JSON schemas and Zod types
4. **Run Tests**: `npm test` for unit/integration coverage
5. **Review Constitution**: [../.specify/memory/constitution.md](../.specify/memory/constitution.md) for governance principles

---

## Support

- **GitHub Issues**: Report bugs and request features
- **Documentation**: See `docs/` directory for API reference
- **Constitution**: Refer to `.specify/memory/constitution.md` for non-negotiable requirements
- **Performance SLOs**: FR-049, FR-050, FR-051 in spec.md

**Constitutional Requirements Summary**:
- ✅ Minimal API (2 tools only): FR-001
- ✅ Branch isolation by default: FR-018
- ✅ 100% audit trail: FR-036, FR-037
- ✅ ADR immutability: FR-038 (via `violatesADRImmutability` helper)
- ✅ P95 < 300ms on ≤3M sections: FR-049

**Happy Hacking! 🚀**
