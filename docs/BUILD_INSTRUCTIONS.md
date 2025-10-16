# Manual Build Instructions for WSL2

**Status**: Docker configuration complete. Follow these steps to build and deploy.

## Issue Encountered

The automated build failed with:
```
/mnt/d/WORKSPACE/tools-node/mcp-cortex: No such file or directory
```

This is a WSL2 path mounting issue. Follow the steps below to resolve and build.

---

## Step 1: Find Correct WSL2 Path

Open WSL2 terminal and try these paths in order:

```bash
# Option A: Lowercase drive mount (common in WSL2)
cd /mnt/d/workspace/tools-node/mcp-cortex
pwd

# Option B: Original path with uppercase
cd /mnt/d/WORKSPACE/tools-node/mcp-cortex
pwd

# Option C: Home directory alternative
cd ~/mcp-cortex  # If you copied project here
pwd

# Option D: List mounts to find correct path
ls -la /mnt/d/
# Find the actual directory name

# Option E: Navigate from Windows path
cd "$(wslpath 'D:\WORKSPACE\tools-node\mcp-cortex')"
pwd
```

**Once you find the correct path**, set it as a variable:
```bash
export PROJECT_PATH="/mnt/d/WORKSPACE/tools-node/mcp-cortex"  # Replace with your actual path
cd "$PROJECT_PATH"
```

---

## Step 2: Verify Files Present

```bash
# Check all Docker files exist
ls -lh Dockerfile docker-compose.yml .dockerignore .env.production

# Expected output:
# -rw-r--r-- Dockerfile
# -rw-r--r-- docker-compose.yml
# -rw-r--r-- .dockerignore
# -rw-r--r-- .env.production
```

If any files are missing, the deployment setup is incomplete.

---

## Step 3: Install Dependencies

```bash
# Install Node.js dependencies (required for build stage)
npm install

# Expected: ~50 packages installed
# Duration: 1-3 minutes

# Verify critical packages
npm list @modelcontextprotocol/sdk zod drizzle-orm pg
```

---

## Step 4: Configure Environment

```bash
# Copy production template to active .env
cp .env.production .env

# CRITICAL: Change default password
nano .env
# Find: DB_PASSWORD=cortex_secure_password_change_me
# Change to: DB_PASSWORD=your_strong_password_min_20_chars

# Or use auto-generated password
openssl rand -base64 32 > .db_password
echo "DB_PASSWORD=$(cat .db_password)" > .env
cat .env.production | grep -v DB_PASSWORD >> .env
```

---

## Step 5: Build Docker Images

```bash
# Build with verbose output
docker-compose build --no-cache --progress=plain

# Expected output (abbreviated):
# [+] Building 45.2s (18/18) FINISHED
# => [builder 1/7] FROM node:20-alpine
# => [builder 5/7] RUN npm ci
# => [builder 6/7] COPY src/ ./src/
# => [builder 7/7] RUN npm run build
# => [runtime 1/5] FROM node:20-alpine
# => [runtime 5/5] USER cortex
# => => naming to docker.io/library/mcp-cortex-server

# If build fails, check errors:
docker-compose build 2>&1 | tee build.log
# Review build.log for specific error
```

### Common Build Errors

**Error: `npm ci` failed**
```bash
# Solution: Ensure package-lock.json exists
ls -lh package-lock.json
# If missing, run npm install to generate it
npm install
docker-compose build --no-cache
```

**Error: TypeScript compilation failed**
```bash
# Solution: Check tsconfig.json and source files
npm run build
# Fix any TypeScript errors before rebuilding Docker image
```

**Error: Docker daemon not running**
```bash
# Solution: Start Docker Desktop on Windows
# Verify with:
docker ps
# Should return empty list or running containers, not connection error
```

---

## Step 6: Start Services

```bash
# Start PostgreSQL and server in detached mode
docker-compose up -d

# Expected output:
# [+] Running 3/3
# ✔ Network cortex_network      Created
# ✔ Container cortex-postgres    Started
# ✔ Container cortex-server      Started

# Check container status
docker-compose ps

# Expected:
# NAME              STATUS         PORTS
# cortex-postgres   Up (healthy)   0.0.0.0:5432->5432/tcp
# cortex-server     Up
```

---

## Step 7: Verify Deployment Health

### 7.1 Check PostgreSQL

```bash
# Test connection
docker exec cortex-postgres pg_isready -U cortex -d cortex_prod
# Output: cortex_prod:5432 - accepting connections

# Verify extensions installed
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "SELECT extname FROM pg_extension WHERE extname IN ('pgcrypto', 'pg_trgm');"
# Output:
#  extname
# ----------
#  pgcrypto
#  pg_trgm
```

### 7.2 Check Migrations Applied

```bash
# List all tables (should see 11 tables)
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "\dt"

# Expected tables:
# - document, section, runbook, pr_context
# - ddl_history, release_note, change_log, issue_log
# - adr_decision, todo_log, event_audit

# Check migration history
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "SELECT migration_id, applied_at FROM ddl_history ORDER BY applied_at;"

# Expected output:
#       migration_id       |         applied_at
# -------------------------+----------------------------
#  0001_initial_schema     | 2025-10-10 ...
#  0002_indexes            | 2025-10-10 ...
#  0003_triggers           | 2025-10-10 ...
```

### 7.3 Check Seed Data

```bash
# Count seeded sections
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "SELECT COUNT(*) FROM section;"
# Expected: > 0 (at least 1 example section)

# View sample data
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "SELECT id, heading, created_at FROM section LIMIT 3;"
```

### 7.4 Check Server Logs

```bash
# View server startup logs
docker-compose logs server | head -20

# Expected log lines:
# {"level":"info","msg":"Cortex Memory MCP server started","transport":"stdio"}
# {"level":"info","msg":"Database pool initialized"}

# Check for errors
docker-compose logs server | grep -i error
# Should return empty (no errors)
```

---

## Step 8: Performance Verification

```bash
# Monitor resource usage
docker stats cortex-server cortex-postgres --no-stream

# Expected baseline (idle):
# CONTAINER         CPU %    MEM USAGE / LIMIT
# cortex-server     1-5%     120-180 MiB
# cortex-postgres   2-8%     200-300 MiB

# Test query latency
time docker exec cortex-postgres psql -U cortex -d cortex_prod -c "SELECT COUNT(*) FROM section;"
# Expected: < 100ms for small dataset
```

---

## Step 9: Functional Testing (Optional)

### Test memory.store Tool

Since the server uses STDIO transport, testing requires MCP client integration. For manual testing:

```bash
# Connect to server container
docker exec -it cortex-server sh

# Send JSON-RPC request (example structure)
# Note: Actual MCP testing requires Claude Code or compatible client
echo '{
  "jsonrpc": "2.0",
  "method": "tools/list",
  "id": 1
}' | node dist/index.js
```

For production integration, configure in your MCP client (Claude Code):
```json
{
  "mcpServers": {
    "cortex": {
      "command": "docker",
      "args": ["exec", "-i", "cortex-server", "node", "dist/index.js"]
    }
  }
}
```

---

## Step 10: Troubleshooting

### Server Container Exits

```bash
# Check exit code
docker-compose ps
# If cortex-server shows Exited (1)

# View full logs
docker-compose logs server

# Common causes:
# 1. Database connection failed (wrong password)
# 2. Migration failed (SQL error)
# 3. Missing environment variable

# Fix: Verify DATABASE_URL
docker-compose config | grep DATABASE_URL
# Should show: postgresql://cortex:YOUR_PASSWORD@postgres:5432/cortex_prod
```

### PostgreSQL Not Healthy

```bash
# Check health status
docker-compose ps postgres
# Should show: Up (healthy)

# If unhealthy, check logs
docker-compose logs postgres

# Wait for health check to pass (may take 10-15 seconds)
watch -n 2 docker-compose ps
```

### Out of Memory

```bash
# If containers crash with OOM
# Increase Docker Desktop memory limit:
# Settings → Resources → Memory → Set to 4GB or more

# Or reduce connection pool
nano .env
# Set: DB_POOL_MAX=5
docker-compose restart
```

---

## Success Criteria

Deployment is successful when all checks pass:

- [ ] `docker-compose ps` shows both containers "Up"
- [ ] `docker exec cortex-postgres pg_isready` returns "accepting connections"
- [ ] `docker exec cortex-postgres psql -U cortex -d cortex_prod -c "\dt"` shows 11 tables
- [ ] `docker-compose logs server` shows "Cortex Memory MCP server started"
- [ ] No ERROR messages in `docker-compose logs`
- [ ] Resource usage within expected ranges (< 200MB RAM per container idle)

---

## Quick Reference Commands

```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# View logs
docker-compose logs -f server

# Restart server
docker-compose restart server

# Shell into server
docker exec -it cortex-server sh

# PostgreSQL shell
docker exec -it cortex-postgres psql -U cortex -d cortex_prod

# Backup database
docker exec cortex-postgres pg_dump -U cortex cortex_prod > backup.sql

# Full cleanup (DESTRUCTIVE)
docker-compose down -v
```

---

## Next Steps After Successful Deployment

1. **Integrate with Claude Code**: Configure MCP client to use STDIO transport
2. **Test Tools**: Send sample memory.store and memory.find requests
3. **Monitor Performance**: Track P95 latency (target: < 300ms)
4. **Setup Backups**: Implement automated daily backup script (see DEPLOYMENT.md)
5. **Review Security**: Ensure DB_PASSWORD is strong, consider network isolation

---

## Support

If deployment fails after following all steps:

1. **Collect Logs**:
   ```bash
   docker-compose logs > full_logs.txt
   docker-compose config > docker_config.txt
   docker version > docker_version.txt
   ```

2. **Verify Environment**:
   ```bash
   uname -r  # Should contain: microsoft-standard-WSL2
   docker --version
   docker-compose --version
   node --version
   npm --version
   ```

3. **Check Documentation**: Review docs/DEPLOYMENT.md for detailed troubleshooting

---

**Build Instructions Status**: Ready for execution
**Last Updated**: 2025-10-10
