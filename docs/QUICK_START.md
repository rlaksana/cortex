# Quick Start - Docker Deployment in WSL2

Get Cortex Memory MCP running in Docker within 5 minutes.

## Prerequisites

- Windows 10/11 with WSL2
- Docker Desktop installed and running
- **PostgreSQL 18+ support**: The system requires PostgreSQL 18 with pgcrypto extension for gen_random_uuid() function

## Step 1: Setup Environment

```bash
# Navigate to project (adjust path as needed)
cd /mnt/d/WORKSPACE/tools-node/mcp-cortex

# Copy environment template
cp .env.production .env

# IMPORTANT: Edit .env and change DB_PASSWORD
nano .env
```

## Step 2: Build and Start

```bash
# Build Docker images
docker-compose build

# Start all services (includes PostgreSQL 18)
docker-compose up -d

# Watch logs
docker-compose logs -f
```

**Note**: The Docker Compose configuration automatically uses PostgreSQL 18 with the required extensions (pgcrypto, pg_trgm).

## Step 3: Verify Deployment

```bash
# Check container status
docker-compose ps
# Both should show "Up" status

# Test database connection and PostgreSQL version
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "SELECT version();"
# Should show PostgreSQL 18.0 or higher

# Test gen_random_uuid() function
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "SELECT gen_random_uuid();"
# Should return a valid UUID

# Test section count
docker exec cortex-postgres psql -U cortex -d cortex_prod -c "SELECT COUNT(*) FROM section;"
# Should return count of seeded sections

# Check server logs
docker-compose logs server | tail -20
# Should see: "Cortex Memory MCP server started"
```

## Step 4: Test MCP Tools

The server is now running in STDIO mode. To test:

```bash
# Connect to server container
docker exec -it cortex-server sh

# You can now send JSON-RPC requests via STDIN
# (For production use, integrate with Claude Code or other MCP clients)
```

## Common Commands

```bash
# Stop services
docker-compose down

# Restart specific service
docker-compose restart server

# View logs
docker-compose logs -f server

# Access PostgreSQL shell
docker exec -it cortex-postgres psql -U cortex -d cortex_prod

# Backup database
docker exec cortex-postgres pg_dump -U cortex cortex_prod > backup.sql
```

## Troubleshooting

### Containers Exit Immediately

```bash
# Check logs for errors
docker-compose logs

# Common fix: Rebuild without cache
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

### Database Connection Refused

```bash
# Wait for PostgreSQL health check
docker-compose ps
# postgres should show "Up (healthy)"

# If not healthy, check logs
docker-compose logs postgres
```

## Next Steps

- Read [DEPLOYMENT.md](./DEPLOYMENT.md) for detailed configuration
- See [../README.md](../README.md) for MCP usage examples
- Check [../specs/001-create-specs-000/quickstart.md](../specs/001-create-specs-000/quickstart.md) for API examples

---

**Need Help?** Check logs with `docker-compose logs -f`
