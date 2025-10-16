# Cortex MCP Auto-Start Solution

## Problem Solved
Cortex MCP sekarang otomatis start saat Claude Code launch, seperti MCP lainnya.

## Root Cause
Cortex tidak memiliki konfigurasi MCP di Claude Code settings, jadi harus dijalankan manual dengan `npm start`.

## Solution Implemented
Created MCP configuration file: `C:\Users\Richard\.claude\mcp\cortex.json`

```json
{
  "name": "cortex",
  "command": "node",
  "args": ["dist/index.js"],
  "cwd": "D:\\WORKSPACE\\tools-node\\mcp-cortex"
}
```

## How It Works
- Claude Code membaca semua file .json di ~/.claude/mcp/
- Setiap file mendefinisikan MCP server yang otomatis dijalankan
- Cortex akan start otomatis saat Claude Code launch
- Tidak perlu npm start manual lagi

## Requirements
1. PostgreSQL harus running di port 5433
2. File dist/index.js harus ada (build sudah dilakukan)
3. Environment variables di .env harus terkonfigurasi

## Auto-Start Process
1. Claude Code launch
2. Baca ~/.claude/mcp/cortex.json
3. Jalankan `node dist/index.js` di project directory
4. Cortex MCP server ready
5. Tidak ada intervensi manual needed

## Cleanup Actions
- Removed globally installed package (npm uninstall -g cortex-memory-mcp)
- Deleted package tarball file
- Kept local configuration only