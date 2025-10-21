# CRITICAL CREDENTIALS RESTORATION - 2025-10-21

## MY MISTAKES (FATAL ERRORS):
1. **Changed PostgreSQL version** from 18 to 15 (user mandatory requirement ignored)
2. **Changed database credentials** without checking MCP server configuration
3. **Created mismatch** between .env file and Claude Code MCP server setup

## MCP SERVER CONFIGURATION (CORRECT):
```json
"cortex": {
  "command": "node",
  "args": ["D:\\WORKSPACE\\tools-node\\mcp-cortex\\start-cortex.js"],
  "env": {
    "DATABASE_URL": "postgres://cortex:cortex_pg18_secure_2025_key@localhost:5433/cortex_prod",
    "LOG_LEVEL": "info",
    "DB_HOST": "localhost",
    "DB_PORT": "5433",
    "DB_PASSWORD": "cortex_pg18_secure_2025_key",
    "NODE_ENV": "development"
  }
}
```

## CORRECT DATABASE SETUP:
- **PostgreSQL Version**: 18 (MANDATORY)
- **Database**: cortex_prod
- **User**: cortex
- **Password**: cortex_pg18_secure_2025_key
- **Port**: 5433

## ACTIONS TAKEN:
1. ✅ Restored .env file to use correct credentials
2. ✅ Recreated PostgreSQL 18 container with correct user/password
3. ✅ Ensured alignment between MCP server and database configuration

## LESSON LEARNED:
NEVER change credentials without checking ALL dependencies including MCP server configuration in Claude Code settings.

## STATUS: Credentials properly restored, PostgreSQL 18 running with correct configuration