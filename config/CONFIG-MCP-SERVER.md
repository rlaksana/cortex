# MCP Configuration Guide for Multiple CLI Tools

## Overview
Cortex Memory MCP Server dengan **single unified index.ts** yang compatible dengan multiple CLI tools:
- Claude Code (Anthropic)
- OpenAI CLI/Codex
- Gemini CLI (Google)

## Universal Configuration

### Environment Variables (Required)
```bash
# OpenAI API (MANDATORY untuk embeddings)
OPENAI_API_KEY=your-openai-api-key

# Qdrant Database (auto-configured)
QDRANT_URL=http://localhost:6333
```

## 1. Claude Code Configuration

### File: `claude_code_config.json`

```json
{
  "mcpServers": {
    "cortex": {
      "command": "node",
      "args": [
        "${PROJECT_ROOT}/dist/index.js"
      ],
      "env": {
        "OPENAI_API_KEY": "${OPENAI_API_KEY}",
        "PROJECT_ROOT": "D:\\WORKSPACE\\tools-node\\mcp-cortex",
        "NODE_ENV": "development",
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

### Cross-Platform Configuration
```json
{
  "mcpServers": {
    "cortex": {
      "command": "node",
      "args": ["${CORTEX_PATH}/dist/index.js"],
      "env": {
        "OPENAI_API_KEY": "${OPENAI_API_KEY}",
        "QDRANT_URL": "${QDRANT_URL:http://localhost:6333}",
        "CORTEX_PATH": "${PROJECT_ROOT}",
        "NODE_ENV": "development"
      }
    }
  }
}
```

### Environment-Based Configuration
```json
{
  "mcpServers": {
    "cortex": {
      "command": "node",
      "args": ["${CORTEX_DIST_PATH}"],
      "env": {
        "OPENAI_API_KEY": "${OPENAI_API_KEY}",
        "QDRANT_URL": "${QDRANT_URL}",
        "NODE_ENV": "${NODE_ENV:development}",
        "LOG_LEVEL": "${LOG_LEVEL:info}"
      }
    }
  }
}
```

## 2. OpenAI CLI / Codex Configuration

### File: `openai-mcp-config.json`

```json
{
  "servers": {
    "cortex": {
      "type": "stdio",
      "command": "node",
      "args": ["${CORTEX_DIST_PATH}"],
      "environment": {
        "OPENAI_API_KEY": "${OPENAI_API_KEY}",
        "QDRANT_URL": "${QDRANT_URL:http://localhost:6333}",
        "CORTEX_DIST_PATH": "${PROJECT_ROOT}/dist/index.js",
        "NODE_ENV": "${NODE_ENV:production}",
        "LOG_LEVEL": "${LOG_LEVEL:warn}"
      },
      "timeout": 30000,
      "retry_attempts": 3
    }
  }
}
```

### Alternative Format (OpenAI CLI v2+)
```json
{
  "mcp": {
    "servers": {
      "cortex-memory": {
        "transport": "stdio",
        "command": "node",
        "args": ["${CORTEX_EXECUTABLE}"],
        "env": {
          "OPENAI_API_KEY": "${OPENAI_API_KEY}",
          "QDRANT_URL": "${QDRANT_URL}",
          "CORTEX_EXECUTABLE": "${PROJECT_ROOT}/dist/index.js"
        },
        "capabilities": {
          "tools": true,
          "streaming": false
        }
      }
    }
  }
}
```

## 3. Gemini CLI Configuration

### File: `gemini-mcp-config.json`

```json
{
  "mcpServers": {
    "cortex": {
      "transport": "stdio",
      "executable": "node",
      "parameters": ["${CORTEX_EXECUTABLE}"],
      "environment": {
        "OPENAI_API_KEY": "${OPENAI_API_KEY}",
        "QDRANT_URL": "${QDRANT_URL:http://localhost:6333}",
        "CORTEX_EXECUTABLE": "${PROJECT_ROOT}/dist/index.js",
        "GOOGLE_AI_SCOPE": "cortex-memory"
      }
    }
  }
}
```

### Google Cloud Integration Format
```json
{
  "gemini": {
    "extensions": {
      "mcp_servers": {
        "cortex": {
          "command": "node",
          "args": ["${CORTEX_BINARY}"],
          "env_vars": {
            "OPENAI_API_KEY": "${OPENAI_API_KEY}",
            "QDRANT_URL": "${QDRANT_URL}",
            "CORTEX_BINARY": "${PROJECT_ROOT}/dist/index.js",
            "LOG_LEVEL": "${LOG_LEVEL:info}"
          },
          "enabled": true
        }
      }
    }
  }
}
```

## 4. Universal MCP Template

### File: `universal-mcp-config.json`

```json
{
  "version": "1.0.0",
  "server": {
    "name": "cortex",
    "description": "Cortex Memory MCP Server - Advanced knowledge management with Qdrant",
    "version": "2.0.0"
  },
  "transport": {
    "type": "stdio",
    "command": "node",
    "args": ["${CORTEX_SERVER_PATH}"],
    "timeout": 30000,
    "retry": {
      "attempts": 3,
      "delay": 1000
    }
  },
  "environment": {
    "OPENAI_API_KEY": "${OPENAI_API_KEY}",
    "QDRANT_URL": "${QDRANT_URL:http://localhost:6333}",
    "CORTEX_SERVER_PATH": "${PROJECT_ROOT}/dist/index.js",
    "NODE_ENV": "${NODE_ENV:development}",
    "LOG_LEVEL": "${LOG_LEVEL:info}"
  },
  "capabilities": {
    "tools": [
      "memory_store",
      "memory_find",
      "database_health",
      "database_stats"
    ],
    "features": [
      "semantic_search",
      "deduplication",
      "multi_strategy_search",
      "scope_isolation"
    ]
  }
}
```

## 5. Docker-Based Configuration

### For Containerized Environments

```json
{
  "mcpServers": {
    "cortex": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "--env", "OPENAI_API_KEY=${OPENAI_API_KEY}",
        "--env", "QDRANT_URL=http://host.docker.internal:6333",
        "cortex-memory:latest"
      ],
      "timeout": 60000
    }
  }
}
```

## 🚫 Anti-Hardcoding Best Practices

### **Why Avoid Hardcoding?**
- **Portability**: Works across different machines and environments
- **Security**: Sensitive data tidak ada di source code
- **Maintainability**: Easy to update without code changes
- **Flexibility**: Multiple deployment scenarios
- **Collaboration**: Team members dapat menggunakan paths berbeda

### **Hardcoded vs Dynamic Examples**

#### ❌ **FORBIDDEN: Hardcoded References**
```json
{
  "args": ["D:\\WORKSPACE\\tools-node\\mcp-cortex\\dist\\index.js"],
  "env": {
    "OPENAI_API_KEY": "sk-proj-fixed-key-12345",
    "QDRANT_URL": "http://localhost:6333"
  }
}
```

```typescript
// ❌ FORBIDDEN in code
const configPath = "D:\\WORKSPACE\\tools-node\\mcp-cortex\\config.json";
const apiKey = "sk-proj-fixed-key-here";
const dbUrl = "http://localhost:6333";
```

#### ✅ **CORRECT: Dynamic Configuration**
```json
{
  "args": ["${CORTEX_EXECUTABLE}"],
  "env": {
    "OPENAI_API_KEY": "${OPENAI_API_KEY}",
    "QDRANT_URL": "${QDRANT_URL:http://localhost:6333}",
    "CORTEX_EXECUTABLE": "${PROJECT_ROOT}/dist/index.js"
  }
}
```

```typescript
// ✅ CORRECT in code
const configPath = process.env.CONFIG_PATH || "./config.json";
const apiKey = process.env.OPENAI_API_KEY;
const dbUrl = process.env.QDRANT_URL || "http://localhost:6333";
```

### **Environment Variable Patterns**

#### **Required Variables**
```bash
# Mandatory (no defaults)
OPENAI_API_KEY=your-openai-api-key

# Optional (with defaults)
QDRANT_URL=${QDRANT_URL:-http://localhost:6333}
PROJECT_ROOT=${PROJECT_ROOT:-$(pwd)}
LOG_LEVEL=${LOG_LEVEL:-info}
NODE_ENV=${NODE_ENV:-development}
```

#### **Path Resolution**
```bash
# Cross-platform path handling
PROJECT_ROOT=$(pwd)                           # Current directory
DIST_PATH="${PROJECT_ROOT}/dist/index.js"    # Dynamic build path
CONFIG_PATH="${CONFIG_PATH:-./config.json}"  # Configurable config
LOG_PATH="${LOG_PATH:-./logs/app.log}"       # Configurable logs
```

## Usage Instructions

### 1. Setup Environment (Cross-Platform)
```bash
# Windows (PowerShell)
$env:OPENAI_API_KEY = "your-key-here"
$env:PROJECT_ROOT = "D:\WORKSPACE\tools-node\mcp-cortex"
$env:QDRANT_URL = "http://localhost:6333"

# Windows (CMD)
set OPENAI_API_KEY=your-key-here
set PROJECT_ROOT=D:\WORKSPACE\tools-node\mcp-cortex
set QDRANT_URL=http://localhost:6333

# Linux/Mac
export OPENAI_API_KEY=your-key-here
export PROJECT_ROOT=/path/to/mcp-cortex
export QDRANT_URL=http://localhost:6333

# Environment file (.env)
OPENAI_API_KEY=your-key-here
PROJECT_ROOT=./
QDRANT_URL=http://localhost:6333
```

### 2. Start Qdrant
```bash
# Docker (portable)
docker run -p 6333:6333 -d --name cortex-qdrant qdrant/qdrant:latest

# Atau gunakan existing container
wsl -d Ubuntu docker start cortex-qdrant

# Atau gunakan service
docker-compose -f docker/docker-compose.yml up -d
```

### 3. Test Connection (Dynamic Paths)
```bash
# Test MCP server dengan dynamic path
export CORTEX_PATH="${PROJECT_ROOT}/dist/index.js"
node ${CORTEX_PATH}

# Atau dengan relative path
node ./dist/index.js

# Test health
curl ${QDRANT_URL}/health
```

## Available Tools

1. **memory_store** - Store knowledge items with semantic deduplication
2. **memory_find** - Multi-strategy semantic search
3. **database_health** - Connection and system health checks
4. **database_stats** - Usage statistics and metrics

## Troubleshooting

### Common Issues
- **Connection timeout**: Increase timeout value in config
- **OpenAI API errors**: Verify API key is valid and has quota
- **Qdrant connection**: Ensure Qdrant is running on port 6333
- **Path issues**: Use absolute paths in configuration

### Debug Mode
```json
{
  "env": {
    "LOG_LEVEL": "debug",
    "ENABLE_DEBUG_MODE": "true"
  }
}
```

## Security Notes

- OpenAI API key disimpan di environment variables, tidak di config files
- Gunakan user-level environment variables untuk keamanan
- Enable logging hanya untuk development
- Production gunakan LOG_LEVEL: "warn" atau "error"