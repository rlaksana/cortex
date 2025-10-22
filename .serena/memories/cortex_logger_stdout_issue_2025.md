# Cortex Logger stdout Issue - 2025-10-22

## Critical Problem Identified
Logger configuration NOT working as expected. Despite `pino.destination(2)` (stderr) in logger.ts:35, ALL log output still goes to stdout.

## Evidence
1. **Logger config**: `void pino.destination(2)` - should write to stderr
2. **Reality**: All JSON log messages appear in stdout, not stderr
3. **Test result**: Even with `NODE_ENV=production`, logger messages still contaminate stdout

## Root Cause Analysis
The issue is NOT with dotenv (already fixed) but with the Pino logger itself. The destination configuration may not be working correctly on Windows/Node.js combination.

## Log Output Contamination Pattern
All initialization logs contaminate stdout:
```json
{"level":"info","time":"2025-10-22T04:25:45.564Z","service":"cortex-mcp","environment":"production","msg":"Environment configuration loaded"}
{"level":"info","time":"2025-10-22T04:25:45.566Z","service":"cortex-mcp","environment":"production","filter":{"sensitiveFields":{"users":["password","password_hash","email","phone"],"sessions":["token","refresh_token"],"api_keys":["key","secret"]}},"msg":"Audit filter configured"}
{"level":"info","time":"2025-10-22T04:25:45.567Z","service":"cortex-mcp","environment":"production","node_env":"production","log_level":"info","mcp_transport":"stdio","db_pool_config":{"min":2,"max":10,"idle_timeout_ms":30000},"msg":"Environment configuration loaded"}
{"level":"info","time":"2025-10-22T04:25:45.567Z","service":"cortex-mcp","environment":"production","resource":"memory_store","action":"write","required_scopes":["memory:write"],"msg":"Added resource access rule"}
```

## MCP Protocol Violation
These JSON log messages in stdout cause:
- JSON-RPC 2.0 parsing errors
- Zod validation failures  
- "Unexpected token" errors
- MCP Inspector cannot distinguish log messages from protocol messages

## Required Fix
**Option 1: Fix Pino Destination**
- Test alternative Pino destination configuration
- Ensure `pino.destination(2)` actually works on Windows

**Option 2: Conditional Logging**
- Disable ALL logging during MCP server startup
- Only enable after MCP transport established
- Use environment variable `MCP_LOG_ENABLED=false`

**Option 3: Separate Log Channels**
- Create MCP-specific logger that uses process.stderr.write()
- Bypass Pino entirely for stdio transport mode

## Status
**BLOCKER**: Logger stdout contamination prevents MCP protocol compliance
**Next**: Fix Pino destination or create MCP-specific logger