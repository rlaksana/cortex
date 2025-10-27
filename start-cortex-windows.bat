@echo off
REM Cortex Memory MCP Server Startup Script for Windows
REM This script sets the required environment variables and starts the MCP server

set OPENAI_API_KEY=your-openai-api-key-here
set NODE_ENV=development
set QDRANT_URL=http://localhost:6333
set QDRANT_COLLECTION_NAME=cortex-memory

echo Starting Cortex Memory MCP Server...
node dist/index-claude.js