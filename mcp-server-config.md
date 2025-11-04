# MCP Server Configuration

## Server Compatibility Requirements

This document outlines the configuration requirements for optimal MCP server compatibility with various clients including Codex CLI.

### Key Configuration Changes Made

1. **SDK Version**: Updated to `@modelcontextprotocol/sdk@^1.0.3` for stability
2. **Node.js Engine**: Set to `>=18.0.0` for broader compatibility
3. **Module Resolution**: Changed from `bundler` to `node` for better import handling
4. **Entry Point**: Simplified to use `dist/index.js` directly
5. **Build Script**: Added executable permission for output files

### MCP Protocol Support

- **Protocol Version**: 2024-11-05
- **Transport**: Stdio (standard input/output)
- **JSON-RPC**: Version 2.0
- **Tools**: Full Cortex Memory toolset supported
- **Resources**: Knowledge graph entities and relations

### Client Compatibility

#### Claude Desktop
```toml
[mcp_servers.cortex]
command = "cortex"
args = []
env = {}
```

#### Codex CLI
```bash
cortex-memory-mcp --stdio
```

#### Direct Node.js Execution
```bash
node dist/index.js
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key for embeddings | Required |
| `QDRANT_URL` | Qdrant vector database URL | `http://localhost:6333` |
| `QDRANT_API_KEY` | Qdrant API key (if needed) | Optional |
| `LOG_LEVEL` | Logging level (debug, info, warn, error) | `info` |
| `NODE_ENV` | Environment (development, production) | `development` |

### Validation Commands

```bash
# Validate MCP server configuration
npm run mcp:validate

# Test MCP protocol communication
npm run mcp:test

# Check configuration compliance
npm run mcp:check-config
```

### Troubleshooting

1. **Module Resolution Issues**: Ensure `moduleResolution` is set to `"node"`
2. **SDK Compatibility**: Use exact version `@modelcontextprotocol/sdk@1.0.3`
3. **Entry Point**: Verify `dist/index.js` exists and is executable
4. **Protocol Errors**: Check JSON-RPC messages follow MCP 2024-11-05 spec

### Build Requirements

```bash
# Standard build with MCP compatibility
npm run build

# Development build with debugging
npm run dev

# Production build
npm run build && npm run prod:validate
```