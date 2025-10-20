# Cortex Memory MCP (MCP-Cortex)

A high-performance Model Context Protocol (MCP) server for durable knowledge management on PostgreSQL. Ships with autonomous decision support, advanced search, a lightweight knowledge graph, strict type-safety, and a full audit trail.

Works great with Claude Desktop (MCP stdio), local dev, CI, or containerized deployments.

## 🚀 **Installation System (Windows)**

For Windows users, we provide a comprehensive one-click installation system:

```powershell
# Clone and install automatically
git clone https://github.com/rlaksana/cortex.git
cd cortex
.\scripts\install.ps1
```

The installer will:
- ✅ Choose between WSL Docker (~800MB) or Docker Desktop (3-5GB)
- ✅ Install PostgreSQL 18 in Docker containers
- ✅ Configure all environment variables
- ✅ Set up automatic backup system
- ✅ Install all dependencies

**Manual installation instructions**: See [docs/INSTALLATION.md](docs/INSTALLATION.md)

## Features

- Knowledge storage: sections, decisions (ADRs), issues, todos, changes, entities, relations, observations, and more
- Smart retrieval: full‑text + trigram fuzzy search, confidence scoring, auto‑correction (optional)
- Graph traversal: follow relations to discover connected knowledge
- Audit + immutability: append-only audit trail, immutable accepted ADRs, write-locked approved docs
- Type-safe end‑to‑end: TypeScript throughout + Zod validation on config
- Operational quality gates: health checks, graceful shutdown, pool metrics

## Requirements

- Node.js 18+
- PostgreSQL 18 (required) with `pgcrypto` and `pg_trgm`
- Git

Prisma is configured with binary targets for Windows (native) and Linux (debian‑openssl‑3.0.x) to support Windows + WSL2.

## Quick Start

### Option A — Local server + Docker PostgreSQL (recommended)

1) Start PostgreSQL 18 via Docker Compose (exposes port 5433 on localhost):

```bash
docker compose -f docker/docker-compose.yml up -d postgres
```

2) Install and build:

```bash
npm install
npm run build
```

3) Configure environment (example matches docker-compose):

```bash
# .env (or export in your shell)
DATABASE_URL=postgresql://cortex:cortex_pg18_secure_2025_key@localhost:5433/cortex_prod
LOG_LEVEL=info
NODE_ENV=development
```

4) Run the MCP server (stdio):

```bash
npm start
# or: node dist/index.js
```

### Option B — Run everything in Docker

See docs/QUICK_START.md and docs/DEPLOYMENT.md for a containerized workflow. The compose file provisions PostgreSQL 18 with required extensions and seeds schema + functions.

## Claude Desktop (MCP) Setup

Add to your Claude Desktop config:

- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "cortex": {
      "command": "node",
      "args": ["<absolute-path-to>/mcp-cortex/start-cortex.js"],
      "env": {
        "DATABASE_URL": "${DATABASE_URL}",
        "LOG_LEVEL": "info",
        "NODE_ENV": "development"
      }
    }
  }
}
```

Tips
- Prefer environment variables; do not hard-code credentials.
- Place a `.env` alongside the Claude config if your launcher reads it, or set OS‑level env vars.

## Available MCP Tools

- `memory_store` — Create/update/delete knowledge with autonomous decision support
- `memory_find` — Retrieve knowledge with fast FTS or deep fuzzy search

Both tools support scope filters (project/branch/org) and return machine‑readable metadata for autonomous flows.

See: specs/001-create-specs-000/contracts/mcp-tools.json and docs/AUTONOMOUS_EXAMPLES.md.

## Configuration

Primary environment variables:

- `DATABASE_URL` (required) — PostgreSQL connection string
- `LOG_LEVEL` — `debug|info|warn|error` (default: `info`)
- `NODE_ENV` — `development|production|test` (default: `development`)
- `MCP_TRANSPORT` — `stdio|http` (default: `stdio`)

Advanced (optional):

- `DB_POOL_MIN` (default: 2)
- `DB_POOL_MAX` (default: 10)
- `DB_IDLE_TIMEOUT_MS` (default: 30000)
- `DB_CONNECTION_TIMEOUT_MS` (default: 10000)
- `DB_MAX_USES` (default: 7500)
- `DB_SSL` (set `true` to enable SSL with `rejectUnauthorized:false`)

## Development

- Install deps: `npm install`
- Type check: `npm run type-check`
- Lint: `npm run lint` (or `lint:fix`)
- Build: `npm run build`
- Tests: `npm test` (see also `test:integration`, `test:e2e`)

Database helpers

- Generate client: `npm run db:generate`
- Push schema: `npm run db:push`
- Migrate dev: `npm run db:migrate`
- Validate: `npm run db:validate`

## Troubleshooting

- PostgreSQL version
  - Run `SELECT version();` and ensure 18.x is reported.
  - Ensure `pgcrypto` and `pg_trgm` are installed (compose initializes them).

- Connection refused on start
  - Compose exposes DB on `localhost:5433`. Verify the container is healthy: `docker compose ps`.

- Prisma binary target mismatch
  - Regenerate client: `npx prisma generate`.
  - Binary targets are set in prisma/schema.prisma: `["native","debian-openssl-3.0.x"]`.

## Docs

- Quick Start: docs/QUICK_START.md
- Deployment: docs/DEPLOYMENT.md
- Architecture: docs/ARCHITECTURE.md
- Build Instructions: docs/BUILD_INSTRUCTIONS.md
- Claude Code Setup: docs/CLAUDE_CODE_SETUP.md
- Postgres Auth/Config: docs/POSTGRES_AUTH_CONFIG.md
- Autonomous Examples: docs/AUTONOMOUS_EXAMPLES.md

## Contributing

- Fork → branch → changes + tests → PR
- Please keep TypeScript strict, run `npm run quality-check` locally.

## License

MIT. See LICENSE if present, otherwise headers in source files.

## Changelog

See CHANGELOG.md and RELEASE_NOTES.md for notable updates.
