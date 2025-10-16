# Deployment Guide - Cortex MCP v1.0.0

Complete guide for deploying Cortex MCP to Docker containers in WSL2.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [WSL2 Setup](#wsl2-setup)
3. [Build and Deploy](#build-and-deploy)
4. [Health Checks](#health-checks)
5. [Configuration](#configuration)
6. [Monitoring](#monitoring)
7. [Troubleshooting](#troubleshooting)
8. [Production Best Practices](#production-best-practices)

---

## Prerequisites

### System Requirements

- **Windows 10/11** with WSL2 enabled
- **Docker Desktop** for Windows with WSL2 backend
- **4GB RAM minimum** (8GB recommended)
- **10GB free disk space**

### WSL2 Installation

```powershell
# In PowerShell (Administrator)
wsl --install
wsl --set-default-version 2
wsl --install -d Ubuntu-22.04
```

### Docker Desktop Configuration

1. Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)
2. Enable WSL2 integration:
   - Settings → Resources → WSL Integration
   - Enable integration with Ubuntu-22.04

### Verify Installation

```bash
# Inside WSL2
docker --version
# Output: Docker version 24.x.x

docker-compose --version
# Output: Docker Compose version v2.x.x

uname -r
# Output should contain: microsoft-standard-WSL2
```

---

## WSL2 Setup

### 1. Navigate to Project Directory

```bash
# In WSL2 terminal
cd /mnt/d/WORKSPACE/tools-node/mcp-cortex

# Or clone from repository
# git clone <your-repo-url> /home/<username>/cortex-memory
# cd /home/<username>/cortex-memory
```

### 2. Verify Project Structure

```bash
ls -la
# Should see:
# - Dockerfile
# - docker-compose.yml
# - src/
# - migrations/
# - package.json
```

### 3. Configure Environment

```bash
# Copy production environment template
cp .env.production .env

# Edit with your settings
nano .env
```

**Required Changes in `.env`:**
```bash
# CRITICAL: Change default password!
DB_PASSWORD=your_secure_password_here_min_20_chars

# Optional customizations
LOG_LEVEL=info
CORTEX_ORG=your-organization
CORTEX_PROJECT=cortex-memory
```

---

## Build and Deploy

### Step 1: Build Docker Images

```bash
# Build the MCP server image
docker-compose build --no-cache

# Expected output:
# [+] Building 45.2s (18/18) FINISHED
# => => naming to docker.io/library/mcp-cortex-server
```

**Build Stages:**
- Stage 1: Install dependencies, compile TypeScript
- Stage 2: Production runtime with non-root user

### Step 2: Start Services

```bash
# Start all services (postgres + server)
docker-compose up -d

# Expected output:
# [+] Running 3/3
# ✔ Network cortex_network      Created
# ✔ Container cortex-postgres    Started
# ✔ Container cortex-server      Started
```

### Step 3: Verify Deployment

```bash
# Check container status
docker-compose ps

# Expected output:
# NAME              STATUS         PORTS
# cortex-postgres   Up (healthy)   0.0.0.0:5432->5432/tcp
# cortex-server     Up

# View server logs
docker-compose logs -f server

# Should see:
# {"level":"info","msg":"Cortex MCP server started","transport":"stdio"}
# {"level":"info","msg":"Database pool initialized"}
```

---

## Health Checks

### Database Health

```bash
# Check PostgreSQL status
docker exec cortex-postgres pg_isready -U cortex -d cortex_prod

# Output: cortex_prod:5432 - accepting connections

# Verify extensions
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "SELECT extname, extversion FROM pg_extension WHERE extname IN ('pgcrypto', 'pg_trgm');"

# Output:
#  extname  | extversion
# ----------+------------
#  pgcrypto | 1.3
#  pg_trgm  | 1.6
```

### Server Health

```bash
# Check server process
docker exec cortex-server ps aux | grep node

# Output: node dist/index.js (running)

# Verify MCP tools registration
docker exec cortex-server node -e "console.log('Server responsive')"
# Output: Server responsive
```

### Database Schema Validation

```bash
# List tables
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "\dt"

# Expected: 11 tables (document, section, runbook, pr_context, ddl_history, release_note, change_log, issue_log, adr_decision, todo_log, event_audit)

# Check migrations applied
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "SELECT migration_id, applied_at FROM ddl_history ORDER BY applied_at;"

# Output:
#       migration_id       |         applied_at
# -------------------------+----------------------------
#  0001_initial_schema     | 2025-10-09 15:40:01.234
#  0002_indexes            | 2025-10-09 15:40:01.456
#  0003_triggers           | 2025-10-09 15:40:01.789
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_PASSWORD` | *required* | PostgreSQL password (20+ chars recommended) |
| `LOG_LEVEL` | `info` | Logging verbosity: debug\|info\|warn\|error |
| `DB_POOL_MIN` | `2` | Minimum database connections |
| `DB_POOL_MAX` | `10` | Maximum database connections |
| `DB_IDLE_TIMEOUT_MS` | `30000` | Idle connection timeout (ms) |
| `CORTEX_ORG` | - | Organization identifier (optional) |
| `CORTEX_PROJECT` | `cortex-memory` | Project name for scope inference |
| `CORTEX_BRANCH` | `main` | Default branch for scope filtering |

### Resource Limits (Optional)

Edit `docker-compose.yml` to add resource constraints:

```yaml
services:
  server:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 512M
```

### Volume Management

```bash
# List volumes
docker volume ls | grep cortex

# Backup database
docker exec cortex-postgres pg_dump -U cortex cortex_prod > backup_$(date +%Y%m%d).sql

# Restore database
cat backup_20251009.sql | docker exec -i cortex-postgres psql -U cortex cortex_prod
```

---

## Monitoring

### Log Management

```bash
# View live logs (all services)
docker-compose logs -f

# View specific service logs
docker-compose logs -f server
docker-compose logs -f postgres

# Search logs
docker-compose logs server | grep ERROR

# Export logs to file
docker-compose logs --no-color > cortex_logs_$(date +%Y%m%d).txt
```

### Performance Metrics

```bash
# Container stats (CPU, Memory, Network)
docker stats cortex-server cortex-postgres

# Expected for 100K sections:
# CONTAINER         CPU %    MEM USAGE / LIMIT    NET I/O
# cortex-server     5.2%     156MiB / 1GiB       12kB / 8kB
# cortex-postgres   12.8%    284MiB / 2GiB       45kB / 32kB
```

### Database Monitoring

```bash
# Active connections
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "SELECT count(*) FROM pg_stat_activity WHERE state = 'active';"

# Table sizes
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "
SELECT
  schemaname,
  tablename,
  pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
"

# Index usage
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "
SELECT
  schemaname,
  tablename,
  indexname,
  idx_scan as index_scans
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC;
"
```

---

## Troubleshooting

### Issue: Server Container Exits Immediately

**Symptoms:**
```bash
docker-compose ps
# cortex-server   Exited (1)
```

**Diagnosis:**
```bash
# Check logs
docker-compose logs server

# Common causes:
# 1. Database connection failed (wrong password)
# 2. Migrations failed (SQL syntax error)
# 3. Missing environment variables
```

**Fix:**
```bash
# Verify DATABASE_URL is correct
docker-compose config | grep DATABASE_URL

# Test database connection
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "SELECT 1;"

# Restart services
docker-compose down
docker-compose up -d
```

### Issue: PostgreSQL Extensions Missing

**Symptoms:**
```
ERROR: extension "pgcrypto" does not exist
```

**Fix:**
```bash
# Manually install extensions
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "CREATE EXTENSION IF NOT EXISTS pgcrypto; CREATE EXTENSION IF NOT EXISTS pg_trgm;"

# Restart server
docker-compose restart server
```

### Issue: Slow Query Performance

**Symptoms:**
```json
{"level":"warn","sql_duration_ms":542,"msg":"Slow SQL query detected"}
```

**Diagnosis:**
```bash
# Check index usage
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "
SELECT schemaname, tablename, indexname, idx_scan
FROM pg_stat_user_indexes
WHERE idx_scan = 0;
"

# Check table statistics
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "ANALYZE VERBOSE;"
```

**Fix:**
```bash
# Rebuild indexes
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "REINDEX DATABASE cortex_prod;"

# Update statistics
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "VACUUM ANALYZE;"
```

### Issue: Out of Memory

**Symptoms:**
```
FATAL: out of memory
```

**Fix:**
```bash
# Increase Docker memory limit in Docker Desktop settings
# Or reduce connection pool size
nano .env
# Set: DB_POOL_MAX=5

# Restart
docker-compose restart
```

---

## Production Best Practices

### Security

1. **Change Default Password:**
   ```bash
   # Generate strong password
   openssl rand -base64 32 > .db_password

   # Add to .env
   echo "DB_PASSWORD=$(cat .db_password)" >> .env
   ```

2. **Network Isolation:**
   ```yaml
   # In docker-compose.yml, remove port mapping if not needed externally
   services:
     postgres:
       # ports:
       #   - "5432:5432"  # Comment out for internal-only access
   ```

3. **Non-Root Container:**
   ```bash
   # Verify server runs as non-root
   docker exec cortex-server whoami
   # Output: cortex
   ```

### Backup Strategy

**Automated Daily Backup:**
```bash
# Create backup script
cat > backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/mnt/d/WORKSPACE/cortex-backups"
mkdir -p "$BACKUP_DIR"
docker exec cortex-postgres pg_dump -U cortex cortex_prod | gzip > "$BACKUP_DIR/cortex_$(date +%Y%m%d_%H%M%S).sql.gz"
# Keep only last 7 days
find "$BACKUP_DIR" -name "cortex_*.sql.gz" -mtime +7 -delete
EOF

chmod +x backup.sh

# Add to crontab
crontab -e
# Add: 0 2 * * * /home/<username>/cortex-memory/backup.sh
```

### Monitoring & Alerts

**Prometheus Metrics (Optional):**
```yaml
# Add to docker-compose.yml
services:
  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
```

### Update Strategy

```bash
# 1. Pull latest code
git pull origin main

# 2. Backup database
./backup.sh

# 3. Rebuild images
docker-compose build --no-cache

# 4. Rolling update (zero downtime)
docker-compose up -d --no-deps --build server

# 5. Verify health
docker-compose ps
docker-compose logs -f server
```

---

## Quick Reference Commands

```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# View logs
docker-compose logs -f

# Restart service
docker-compose restart server

# Execute SQL query
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "SELECT COUNT(*) FROM section;"

# Shell into server
docker exec -it cortex-server sh

# Shell into PostgreSQL
docker exec -it cortex-postgres psql -U cortex -d cortex_prod

# Remove all data (DESTRUCTIVE)
docker-compose down -v

# Rebuild from scratch
docker-compose down -v && docker-compose build --no-cache && docker-compose up -d
```

---

## Support

For issues or questions:
- **GitHub Issues**: Report deployment problems
- **Logs**: Always include `docker-compose logs` output
- **System Info**: Include `docker version`, `docker-compose version`, `wsl --version`

---

## License

MIT - See [LICENSE](../LICENSE) file for details.
