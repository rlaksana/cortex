@echo off
echo Starting Cortex MCP Server...
cd /d "D:\WORKSPACE\tools-node\mcp-cortex"

REM Check if PostgreSQL is running
netstat -ano | findstr :5433 > nul
if %errorlevel% neq 0 (
    echo ERROR: PostgreSQL is not running on port 5433
    echo Please start PostgreSQL Docker container first
    pause
    exit /b 1
)

REM Start Cortex MCP server
echo Starting Cortex MCP server on stdio transport...
node dist/index.js

if %errorlevel% neq 0 (
    echo ERROR: Cortex MCP server failed to start
    pause
    exit /b 1
)

echo Cortex MCP server started successfully