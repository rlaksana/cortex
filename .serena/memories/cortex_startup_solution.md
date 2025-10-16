# Cortex MCP Startup Solution

## Problem Identified
Cortex MCP server fails to start automatically after Claude Code restart due to:
1. Manual server startup required
2. No automatic process management
3. PostgreSQL dependency check needed

## Solutions Implemented

### 1. Startup Scripts Created
- `start-cortex.bat` - Windows batch script with PostgreSQL check
- `start-cortex.js` - Node.js script with proper error handling
- `package.json` - Proper npm scripts for development

### 2. Usage Commands
```bash
# Start Cortex with automatic checks
npm start

# Start Cortex directly
npm run start:raw

# Development mode
npm run dev

# Test database connection
npm run test:connection
```

### 3. Features Added
- PostgreSQL connection validation
- Graceful shutdown handling
- Error reporting and logging
- Process status monitoring
- Development-friendly scripts

## Root Cause Analysis
- MCP servers using stdio transport run as separate processes
- Claude Code doesn't automatically restart MCP servers
- Manual startup required after each Claude Code restart

## Permanent Solution
1. Use the new startup scripts: `npm start`
2. Ensure PostgreSQL Docker container is running
3. Server will automatically validate dependencies before starting

## Multi-Instance Support (Future)
- Different DATABASE_URL for each instance
- Separate Docker containers
- Connection pooling configuration