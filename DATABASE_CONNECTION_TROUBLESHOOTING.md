# Database Connection Troubleshooting Guide

## Overview
This guide provides comprehensive troubleshooting steps for database connectivity issues with the mcp-cortex project using PostgreSQL in WSL2.

## Architecture
- **Database**: PostgreSQL 16 running in WSL2 Ubuntu
- **Connection Port**: 5432 (forwarded via WSL relay)
- **Database User**: `cortex`
- **Database Name**: `cortex_prod`
- **Connection Method**: Direct TCP connection through WSL relay

## Configuration Files

### Primary Configuration (.env)
```bash
# Database Connection (Local PostgreSQL Development)
DATABASE_URL=postgresql://cortex:cortex_pg18_secure_2025_key@localhost:5432/cortex_prod
DB_HOST=localhost
DB_PORT=5432
DB_NAME=cortex_prod
DB_USER=cortex
DB_PASSWORD=cortex_pg18_secure_2025_key
```

### Alternative Configuration Files
- `.env.development` - Development environment settings
- `.env.example` - Template for new configurations
- `.env.wsl` - WSL-specific settings

## Common Issues and Solutions

### 1. Port Conflicts (5432 vs 5433)
**Problem**: Configuration pointing to wrong port
**Symptoms**: `ECONNREFUSED` errors
**Solution**:
```bash
# Check what's listening on PostgreSQL ports
netstat -an | findstr 5432
netstat -an | findstr 5433

# Update configuration to use correct port (5432 for WSL2 PostgreSQL)
DB_PORT=5432
```

### 2. Environment Variable Caching
**Problem**: System environment variables override .env files
**Symptoms**: Changes to .env not taking effect
**Solution**:
```bash
# Clear cached environment variables
unset DB_PORT
unset DATABASE_URL

# Verify .env file is loaded correctly
node -e "require('dotenv').config(); console.log('DB_PORT:', process.env.DB_PORT);"
```

### 3. User Authentication Issues
**Problem**: PostgreSQL user doesn't exist or incorrect password
**Symptoms**: `password authentication failed for user "cortex"`
**Solution**:
```bash
# Create PostgreSQL user in WSL2
wsl -d Ubuntu bash -c "sudo -u postgres psql -c \"CREATE USER cortex WITH PASSWORD 'cortex_pg18_secure_2025_key';\""

# Create database
wsl -d Ubuntu bash -c "sudo -u postgres psql -c \"CREATE DATABASE cortex_prod OWNER cortex;\""

# Grant privileges
wsl -d Ubuntu bash -c "sudo -u postgres psql -c \"GRANT ALL PRIVILEGES ON DATABASE cortex_prod TO cortex;\""
```

### 4. Database Service Not Running
**Problem**: PostgreSQL service not started in WSL2
**Symptoms**: Connection timeouts, `ECONNREFUSED` errors
**Solution**:
```bash
# Check PostgreSQL service status
wsl -d Ubuntu bash -c "systemctl status postgresql"

# Start PostgreSQL service
wsl -d Ubuntu bash -c "sudo systemctl start postgresql"

# Enable service to start on boot
wsl -d Ubuntu bash -c "sudo systemctl enable postgresql"
```

### 5. Line Ending Issues
**Problem**: Windows line endings in .env files cause parsing issues
**Symptoms**: Environment variables not loaded correctly
**Solution**:
```bash
# Recreate .env file with proper line endings
# Use a text editor that supports Unix line endings (LF)
# Or create new .env file using echo commands

# Verify line endings
cat -A .env  # Look for ^M$ characters (Windows CRLF)
```

## Testing Procedures

### 1. Basic Connection Test
```bash
# Test direct PostgreSQL connection
node -e "
require('dotenv').config();
const { Pool } = require('pg');
const pool = new Pool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
});
pool.query('SELECT NOW() as current_time')
  .then(result => {
    console.log('✅ Direct DB connection OK');
    console.log('Current time:', result.rows[0].current_time);
    return pool.end();
  })
  .catch(err => {
    console.error('❌ Direct DB connection failed:', err.message);
    pool.end();
  });
"
```

### 2. Application Connection Test
```bash
# Test application database pool
npm run test:connection

# Test Prisma client connection
npm run db:health
```

### 3. Database Schema Validation
```bash
# Push Prisma schema to database
npx prisma db push

# Validate schema synchronization
npx prisma validate
```

### 4. Full Database Reset (if needed)
```bash
# Reset database (WARNING: Deletes all data)
npx prisma migrate reset

# Or drop and recreate manually
wsl -d Ubuntu bash -c "sudo -u postgres psql -c \"DROP DATABASE IF EXISTS cortex_prod;\""
wsl -d Ubuntu bash -c "sudo -u postgres psql -c \"CREATE DATABASE cortex_prod OWNER cortex;\""
```

## Configuration Validation

### Environment Variables Check
```bash
# Verify all required variables are set
echo "DB_HOST: $DB_HOST"
echo "DB_PORT: $DB_PORT"
echo "DB_NAME: $DB_NAME"
echo "DB_USER: $DB_USER"
echo "DB_PASSWORD: ${DB_PASSWORD:+***}"
echo "DATABASE_URL: $DATABASE_URL"
```

### WSL2 Service Status
```bash
# Check PostgreSQL processes
wsl -d Ubuntu bash -c "ps aux | grep postgres"

# Check service status
wsl -d Ubuntu bash -c "systemctl status postgresql"

# Check port listening
wsl -d Ubuntu bash -c "netstat -tlnp | grep 5432"
```

### Database Objects Verification
```bash
# List users
wsl -d Ubuntu bash -c "sudo -u postgres psql -c 'SELECT usename FROM pg_user ORDER BY usename;'"

# List databases
wsl -d Ubuntu bash -c "sudo -u postgres psql -c 'SELECT datname, datdba::regrole as owner FROM pg_database WHERE datistemplate = false ORDER BY datname;'"

# Check table existence
wsl -d Ubuntu bash -c "sudo -u postgres psql -c 'SELECT tablename FROM pg_tables WHERE schemaname = \"public\";'"
```

## Performance Tuning

### Connection Pool Settings
```bash
# Optimized for local development
DB_POOL_MIN=2
DB_POOL_MAX=10
DB_IDLE_TIMEOUT_MS=30000
DB_CONNECTION_TIMEOUT_MS=10000
DB_QUERY_TIMEOUT=30000
DB_STATEMENT_TIMEOUT=30000
```

### PostgreSQL Configuration (WSL2)
```bash
# Edit PostgreSQL configuration
wsl -d Ubuntu bash -c "sudo nano /etc/postgresql/16/main/postgresql.conf"

# Key settings for local development
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 64MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
```

## Security Considerations

### Password Security
- Use strong passwords for database users
- Store passwords securely in environment files
- Never commit passwords to version control
- Consider using password managers for production

### Network Security
- PostgreSQL is accessible only through WSL relay
- Consider firewall rules for additional security
- Use SSL connections in production environments

### User Privileges
- Grant minimal necessary privileges to application users
- Use different users for different applications
- Regular user permission audits

## Frequently Asked Questions

### Q: Why is PostgreSQL running on port 5432 and not 5433?
A: PostgreSQL 16 in WSL2 uses the default port 5432. The relay service forwards this port to Windows. Port 5433 is typically used for alternative PostgreSQL instances.

### Q: Why do I need to unset environment variables?
A: System environment variables take precedence over .env files. Cached variables from previous configurations may override your current settings.

### Q: How do I know if the database is working?
A: Run `npm run db:health` - it should return "✅ DB healthy" with proper configuration.

### Q: What if I forget the database password?
A: You can reset it in WSL2:
```bash
wsl -d Ubuntu bash -c "sudo -u postgres psql -c \"ALTER USER cortex PASSWORD 'new_password';\""
```

### Q: Can I use a different database?
A: Yes, update the DATABASE_URL and individual DB_* variables in your .env file to point to your preferred database.

## Support

For additional support:
1. Check the application logs: `tail -f logs/app.log`
2. Verify PostgreSQL logs: `wsl -d Ubuntu bash -c "sudo tail -f /var/log/postgresql/postgresql-16-main.log"`
3. Run the full test suite: `npm test`
4. Check GitHub issues for similar problems

---

Last updated: 2025-10-22
Database version: PostgreSQL 16.10 (Ubuntu 16.10-0ubuntu0.24.04.1)
Architecture: WSL2 Ubuntu relay to Windows