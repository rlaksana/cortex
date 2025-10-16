# Claude Code Setup Guide - Cortex MCP

**Version**: 1.1.0
**Date**: 2025-10-13

---

## Prerequisites

1. **PostgreSQL 18+** installed and running
2. **Node.js 20+** installed
3. **Project built**: Run `npm run build` in project directory
4. **Database migrated**: Run `npm run db:migrate`

---

## Step 1: Build the MCP Server

```bash
cd D:\WORKSPACE\tools-node\mcp-cortex

# Install dependencies
npm install

# Build TypeScript to dist/
npm run build

# Verify dist/index.js exists
ls dist/index.js
```

---

## Step 2: Setup PostgreSQL Database

### Option A: Using Docker (Recommended)

```bash
# Start PostgreSQL container
docker-compose up -d

# Wait for database to be ready
timeout 10

# Run migrations
npm run db:migrate

# (Optional) Seed sample data
npm run db:seed
```

### Option B: Local PostgreSQL

```bash
# Create database
createdb cortex_dev

# Create user
psql -c "CREATE USER cortex WITH PASSWORD 'cortex_dev_password';"
psql -c "GRANT ALL PRIVILEGES ON DATABASE cortex_dev TO cortex;"

# Run migrations
npm run db:migrate
```

---

## Step 3: Configure Claude Code Settings

### Locate Settings File

**Windows**: `C:\Users\{YourUsername}\.claude\settings.json`
**macOS**: `~/.claude/settings.json`
**Linux**: `~/.claude/settings.json`

### Add MCP Server Configuration

Add the following to your `settings.json` under `"mcpServers"`:

```json
{
  "mcpServers": {
    "cortex-memory": {
      "command": "node",
      "args": [
        "D:\\WORKSPACE\\tools-node\\mcp-cortex\\dist\\index.js"
      ],
      "env": {
        "DATABASE_URL": "postgresql://cortex:cortex_dev_password@localhost:5432/cortex_dev",
        "LOG_LEVEL": "info",
        "NODE_ENV": "production",
        "CORTEX_ORG": "my-org",
        "CORTEX_PROJECT": "cortex-memory",
        "CORTEX_BRANCH": "main"
      }
    }
  }
}
```

**Important**: Replace paths with your actual installation paths.

---

## Step 4: Understanding MCP Tool Approval

### ⚠️ Important: Tool Approval Prompts

**Claude Desktop will prompt you to approve each MCP tool invocation** - this is expected and intentional behavior!

When Claude wants to use `memory.store` or `memory.find`, you'll see a prompt like:
```
┌─────────────────────────────────────────────┐
│ Allow cortex-memory to call memory.store?  │
│                                             │
│ [Allow]  [Deny]  [Allow for Session]       │
└─────────────────────────────────────────────┘
```

### Why Tool Approval is Required

**MCP Security Model:**
- All MCP tool calls require **explicit user approval** by design
- This prevents malicious or unintended actions without your knowledge
- From official MCP docs: "All actions require your explicit approval"

**Configuration Fields (Official):**
```json
{
  "mcpServers": {
    "cortex-memory": {
      "command": "node",      // ✅ Required: Command to launch server
      "args": ["path"],       // ✅ Required: Arguments for server
      "env": {                // ✅ Optional: Environment variables
        "DATABASE_URL": "..."
      }
      // ❌ NO "alwaysAllow" field exists
      // ❌ NO "disabled" field exists
      // ❌ NO auto-approval mechanism
    }
  }
}
```

**Source:** [Official MCP Documentation](https://modelcontextprotocol.io/docs/develop/connect-local-servers)

### What You Can Control

- **Database Access**: Controlled via `DATABASE_URL` environment variable
- **Server Lifecycle**: Start/stop MCP server via Claude Code
- **Tool Approval**: Accept/deny each tool invocation when prompted

---

## Step 5: Verify Setup

### Test 1: Check MCP Server Starts

```bash
# Run server manually to verify
cd D:\WORKSPACE\tools-node\mcp-cortex
npm start

# Should see:
# {"level":30,"time":...,"transport":"stdio","msg":"Cortex MCP server started"}
```

Press Ctrl+C to stop after verification.

### Test 2: Claude Code Integration

1. **Restart Claude Code** (to reload settings.json)
2. **Open any project** in Claude Code
3. **Type command**: `/mcp list` or check MCP status
4. **Verify**: "cortex-memory" appears in MCP servers list

### Test 3: Use the Tools

**Example 1: Store knowledge**
```
User: Store this decision in cortex memory:
"Use OAuth 2.0 for authentication because it's industry standard"
```

Claude Code should use `memory.store` tool.

**Example 2: Search knowledge**
```
User: Search cortex memory for authentication decisions
```

Claude Code should use `memory.find` tool.

---

## Complete settings.json Example

```json
{
  "mcpServers": {
    "cortex-memory": {
      "command": "node",
      "args": [
        "D:\\WORKSPACE\\tools-node\\mcp-cortex\\dist\\index.js"
      ],
      "env": {
        "DATABASE_URL": "postgresql://cortex:cortex_dev_password@localhost:5432/cortex_dev",
        "LOG_LEVEL": "info",
        "NODE_ENV": "production",
        "MCP_TRANSPORT": "stdio",
        "CORTEX_ORG": "my-org",
        "CORTEX_PROJECT": "cortex-memory",
        "CORTEX_BRANCH": "main",
        "DB_POOL_MIN": "2",
        "DB_POOL_MAX": "10",
        "DB_IDLE_TIMEOUT_MS": "30000"
      }
    }
  }
}
```

---

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | YES | - | PostgreSQL connection string |
| `LOG_LEVEL` | NO | `info` | Logging level (debug, info, warn, error) |
| `NODE_ENV` | NO | `development` | Environment (development, production) |
| `MCP_TRANSPORT` | NO | `stdio` | MCP transport protocol |
| `CORTEX_ORG` | NO | - | Organization identifier (for scope inference) |
| `CORTEX_PROJECT` | NO | - | Project name (for scope inference) |
| `CORTEX_BRANCH` | NO | - | Git branch (for scope inference) |
| `DB_POOL_MIN` | NO | `2` | Min database connections |
| `DB_POOL_MAX` | NO | `10` | Max database connections |
| `DB_IDLE_TIMEOUT_MS` | NO | `30000` | Connection idle timeout |

---

## Troubleshooting

### Issue: MCP Server Not Showing in Claude Code

**Solution**:
1. Check settings.json syntax (valid JSON)
2. Restart Claude Code
3. Verify file paths are absolute (not relative)
4. Check Node.js version: `node --version` (should be 20+)

### Issue: Database Connection Failed

**Solution**:
1. Verify PostgreSQL is running: `docker ps` or `pg_isready`
2. Check DATABASE_URL credentials
3. Test connection manually:
   ```bash
   psql "postgresql://cortex:cortex_dev_password@localhost:5432/cortex_dev"
   ```

### Issue: "Module not found" Error

**Solution**:
1. Rebuild project: `npm run build`
2. Verify dist/index.js exists
3. Check package.json "type": "module" is set

### Issue: Tool Approval Prompts Appearing

**This is NOT an error** - it's expected MCP behavior!

**What's Happening**:
Claude Desktop prompts you to approve each MCP tool call (memory.find, memory.store) for security.

**Solution**:
- Click **"Allow for Session"** to approve for current conversation
- This is intentional security design - there is no way to permanently disable prompts
- See "MCP Tool Approval Reference" section above for details

### Issue: Slow Performance

**Solution**:
1. Check database indexes: `npm run db:migrate` (ensures indexes created)
2. Increase connection pool: Set `DB_POOL_MAX=20`
3. Enable query logging: Set `LOG_LEVEL=debug`

---

## Production Configuration

For production deployments, use:

```json
{
  "mcpServers": {
    "cortex-memory": {
      "command": "node",
      "args": [
        "D:\\WORKSPACE\\tools-node\\mcp-cortex\\dist\\index.js"
      ],
      "env": {
        "DATABASE_URL": "postgresql://cortex_user:STRONG_PASSWORD@prod-db.example.com:5432/cortex_prod",
        "LOG_LEVEL": "warn",
        "NODE_ENV": "production",
        "MCP_TRANSPORT": "stdio",
        "CORTEX_ORG": "your-org",
        "CORTEX_PROJECT": "your-project",
        "DB_POOL_MIN": "5",
        "DB_POOL_MAX": "20",
        "DB_IDLE_TIMEOUT_MS": "60000"
      }
    }
  }
}
```

**Production Checklist**:
- [ ] Use strong database password
- [ ] Enable SSL for database connection
- [ ] Set LOG_LEVEL to "warn" or "error"
- [ ] Increase connection pool size (DB_POOL_MAX=20)
- [ ] Configure database backups
- [ ] Monitor performance metrics

---

## Security Considerations

### Database Access

**Recommended**:
- Create dedicated database user with minimal privileges
- Use SSL/TLS for database connections
- Rotate database passwords regularly

```sql
-- Create restricted user
CREATE USER cortex_restricted WITH PASSWORD 'strong_password';

-- Grant minimal privileges
GRANT CONNECT ON DATABASE cortex_prod TO cortex_restricted;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO cortex_restricted;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO cortex_restricted;

-- Revoke dangerous privileges
REVOKE DELETE ON ALL TABLES IN SCHEMA public FROM cortex_restricted;
```

### Environment Variables

**Recommended**:
- Store DATABASE_URL in environment variable (not settings.json)
- Use secrets manager for production
- Never commit credentials to git

**Windows Example**:
```powershell
# Set environment variable
[System.Environment]::SetEnvironmentVariable('CORTEX_DATABASE_URL', 'postgresql://...', 'User')
```

Then use in settings.json:
```json
"env": {
  "DATABASE_URL": "${CORTEX_DATABASE_URL}"
}
```

---

## Advanced Configuration

### Custom Branch Inference

If not using git context, explicitly set branch in environment:

```json
"env": {
  "CORTEX_BRANCH": "feature/my-feature"
}
```

### Multiple Instances (per Project)

You can configure multiple cortex-memory instances for different projects:

```json
{
  "mcpServers": {
    "cortex-project-a": {
      "command": "node",
      "args": ["D:\\...\\dist\\index.js"],
      "env": {
        "DATABASE_URL": "postgresql://...@localhost:5432/project_a_db",
        "CORTEX_PROJECT": "project-a"
      }
    },
    "cortex-project-b": {
      "command": "node",
      "args": ["D:\\...\\dist\\index.js"],
      "env": {
        "DATABASE_URL": "postgresql://...@localhost:5432/project_b_db",
        "CORTEX_PROJECT": "project-b"
      }
    }
  }
}
```

### Remote Database

For remote PostgreSQL:

```json
"env": {
  "DATABASE_URL": "postgresql://user:pass@remote-host.com:5432/dbname?sslmode=require"
}
```

---

## Testing the Setup

### Quick Test Script

Create `test-cortex.js`:

```javascript
// test-cortex.js
import { spawn } from 'child_process';

const server = spawn('node', ['dist/index.js'], {
  env: {
    ...process.env,
    DATABASE_URL: 'postgresql://cortex:cortex_dev_password@localhost:5432/cortex_dev'
  }
});

// Send tools/list request
const request = {
  jsonrpc: '2.0',
  id: 1,
  method: 'tools/list',
  params: {}
};

server.stdin.write(JSON.stringify(request) + '\n');

server.stdout.on('data', (data) => {
  console.log('Response:', data.toString());
  server.kill();
});

server.stderr.on('data', (data) => {
  console.error('Error:', data.toString());
});
```

Run test:
```bash
node test-cortex.js
```

Expected output:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {"name": "memory.find", "description": "..."},
      {"name": "memory.store", "description": "..."}
    ]
  }
}
```

---

## Integration Examples

### Example 1: Store Architecture Decision

In Claude Code chat:
```
Store this ADR in memory:

Title: Use PostgreSQL for MCP Cortex
Component: database
Status: accepted
Rationale: PostgreSQL provides ACID guarantees, excellent FTS support, and scales to millions of records. The pg_trgm extension enables fuzzy matching for deep search mode.
```

Claude Code will use:
```typescript
memory.store({
  items: [{
    kind: "decision",
    scope: { project: "cortex-memory", branch: "main" },
    data: {
      component: "database",
      status: "accepted",
      title: "Use PostgreSQL for MCP Cortex",
      rationale: "PostgreSQL provides ACID guarantees...",
      alternatives_considered: ["SQLite", "MongoDB"]
    }
  }]
})
```

### Example 2: Search for Previous Decisions

In Claude Code chat:
```
Search cortex memory for database-related decisions
```

Claude Code will use:
```typescript
memory.find({
  query: "database decisions",
  types: ["decision"],
  mode: "auto"
})
```

### Example 3: Track Task Progress (Graph Extension)

In Claude Code chat:
```
Create a task in cortex memory and track its progress
```

Claude Code will use:
```typescript
// Create task
const taskResult = await memory.store({
  items: [{
    kind: "todo",
    scope: { project: "cortex-memory", branch: "main" },
    data: {
      scope: "feature/auth",
      todo_type: "task",
      text: "Implement OAuth 2.0",
      status: "in_progress"
    }
  }]
});

// Add progress observation
await memory.store({
  items: [{
    kind: "observation",
    data: {
      entity_type: "todo",
      entity_id: taskResult.stored[0].id,
      observation: "progress: 50% | milestone: OAuth provider integrated"
    }
  }]
});
```

---

## Complete settings.json Template

```json
{
  "mcpServers": {
    "cortex-memory": {
      "command": "node",
      "args": [
        "D:\\WORKSPACE\\tools-node\\mcp-cortex\\dist\\index.js"
      ],
      "env": {
        "DATABASE_URL": "postgresql://cortex:cortex_dev_password@localhost:5432/cortex_dev",
        "LOG_LEVEL": "info",
        "NODE_ENV": "production",
        "MCP_TRANSPORT": "stdio",
        "CORTEX_ORG": "my-org",
        "CORTEX_PROJECT": "cortex-memory",
        "CORTEX_BRANCH": "main",
        "DB_POOL_MIN": "2",
        "DB_POOL_MAX": "10",
        "DB_IDLE_TIMEOUT_MS": "30000"
      }
    }
  },
  "globalShortcut": "CommandOrControl+Shift+.",
  "theme": "dark"
}
```

---

## MCP Tool Approval Reference

### Default Behavior

**All MCP tool invocations require user approval** - there is no configuration option to bypass this.

This is a fundamental security feature of the MCP protocol, not a limitation or bug.

### Per-Session Approval

When prompted, you can click **"Allow for Session"** to approve a tool for the duration of your current Claude Code session. This avoids repeated prompts within the same conversation.

### Common Misconceptions

❌ **MYTH**: There's an `alwaysAllow` field to auto-approve tools
✅ **FACT**: No such field exists in MCP configuration

❌ **MYTH**: Tool prompts can be permanently disabled
✅ **FACT**: Prompts are intentional security design

❌ **MYTH**: This is a Claude Code-specific limitation
✅ **FACT**: This is part of the MCP protocol specification

### Official Configuration Schema

The `mcpServers` configuration only supports these fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `command` | string | ✅ Yes | Command to launch MCP server |
| `args` | array | ✅ Yes | Arguments passed to command |
| `env` | object | ❌ No | Environment variables |

**Source**: [Model Context Protocol Specification](https://modelcontextprotocol.io/docs/develop/connect-local-servers)

---

## Database Connection Strings

### Local Development

```
postgresql://cortex:cortex_dev_password@localhost:5432/cortex_dev
```

### Docker Container

```
postgresql://cortex:cortex_dev_password@host.docker.internal:5432/cortex_dev
```

### Remote PostgreSQL

```
postgresql://user:password@db.example.com:5432/cortex_prod?sslmode=require
```

### Connection Pool Settings

```
postgresql://user:pass@host:5432/db?
  application_name=cortex-mcp&
  connect_timeout=10&
  statement_timeout=30000&
  idle_in_transaction_session_timeout=60000
```

---

## Monitoring & Logs

### Enable Debug Logging

```json
"env": {
  "LOG_LEVEL": "debug"
}
```

### Log Output Location

**Windows**: Claude Code console (View > Developer > Toggle Developer Tools)
**macOS/Linux**: Check Claude Code logs directory

### View Logs in Real-Time

```bash
# Follow logs
tail -f ~/.claude/logs/mcp-cortex-memory.log
```

---

## Health Checks

### Database Health

```sql
-- Check connection
SELECT 1;

-- Check tables exist
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;
-- Should show 14 tables

-- Check indexes
SELECT indexname FROM pg_indexes
WHERE schemaname = 'public'
ORDER BY indexname;
-- Should show 30+ indexes

-- Check recent activity
SELECT COUNT(*) as total_sections FROM section;
SELECT COUNT(*) as total_decisions FROM adr_decision;
SELECT COUNT(*) as total_entities FROM knowledge_entity;
```

### MCP Server Health

```bash
# Test MCP protocol manually
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | node dist/index.js
```

Expected response:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {"name": "memory.find", ...},
      {"name": "memory.store", ...}
    ]
  }
}
```

---

## Upgrade Path

### Updating Cortex Memory

```bash
# 1. Pull latest changes
git pull origin main

# 2. Install dependencies
npm install

# 3. Run migrations (if any)
npm run db:migrate

# 4. Rebuild
npm run build

# 5. Restart Claude Code (reload MCP server)
```

### Database Migrations

Migrations are located in `migrations/` directory:
- `001_initial_schema.sql` - Base tables
- `002_indexes.sql` - Performance indexes
- `003_triggers.sql` - Audit + immutability
- `004_add_graph_schema.sql` - Graph extension (v1.1.0)

Run migrations:
```bash
npm run db:migrate
```

---

## FAQ

**Q: Can I use multiple databases?**
A: Yes, configure multiple MCP server instances with different DATABASE_URL values.

**Q: How do I backup the knowledge base?**
A: Use PostgreSQL backup tools:
```bash
pg_dump cortex_dev > backup.sql
```

**Q: Can I use this with other AI tools besides Claude Code?**
A: Yes, any MCP-compatible client can connect via STDIO transport.

**Q: What happens if database is unavailable?**
A: MCP tools will fail gracefully with error messages. Claude Code will show the error to user.

**Q: How do I reset the database?**
A: Drop and recreate:
```bash
dropdb cortex_dev
createdb cortex_dev
npm run db:migrate
```

**Q: Can I use Windows paths with backslashes?**
A: Yes, but escape them: `"D:\\WORKSPACE\\..."` or use forward slashes: `"D:/WORKSPACE/..."`

---

## Support

**Documentation**:
- Main README: README.md
- API Reference: specs/001-create-specs-000/spec.md
- Migration Guide: specs/001-create-specs-000/graph-migration-guide.md
- Comparison: docs/MCP_Memory_Comparison.md

**Issues**:
- Report bugs or feature requests via GitHub Issues
- Check existing documentation before reporting

---

## Quick Reference Card

```
SETUP COMMANDS:
===============
npm install              # Install dependencies
npm run build            # Compile TypeScript
npm run db:migrate       # Run database migrations
npm start                # Start MCP server (manual test)

SETTINGS.JSON LOCATION:
=======================
Windows: C:\Users\{You}\.claude\settings.json
macOS:   ~/.claude/settings.json
Linux:   ~/.claude/settings.json

MINIMUM CONFIGURATION:
======================
{
  "mcpServers": {
    "cortex-memory": {
      "command": "node",
      "args": ["D:\\WORKSPACE\\tools-node\\mcp-cortex\\dist\\index.js"],
      "env": {
        "DATABASE_URL": "postgresql://cortex:pass@localhost:5432/cortex_dev"
      }
    }
  }
}

VERIFY SETUP:
=============
1. Restart Claude Code
2. Check MCP servers list
3. Try: "Search cortex memory for test"
```

---

**Setup Status**: Ready for configuration
**Risk**: Low (standard MCP setup)
**Estimated Time**: 10 minutes (if database already running)
