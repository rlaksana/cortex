#!/usr/bin/env node
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Start the Cortex MCP server
const serverPath = path.join(__dirname, 'dist', 'index.js');
const child = spawn('node', [serverPath], {
  stdio: 'inherit',
  env: {
    ...process.env,
    // Override with MCP client environment if provided
    DATABASE_URL: process.env.DATABASE_URL || 'postgresql://cortex:cortex_pg18_secure_2025_key@localhost:5433/cortex_prod',
    LOG_LEVEL: process.env.LOG_LEVEL || 'info',
    DB_HOST: process.env.DB_HOST || 'localhost',
    DB_PORT: process.env.DB_PORT || '5433',
    DB_PASSWORD: process.env.DB_PASSWORD || 'cortex_pg18_secure_2025_key',
    NODE_ENV: process.env.NODE_ENV || 'development'
  }
});

child.on('error', (error) => {
  console.error('Failed to start Cortex MCP server:', error);
  process.exit(1);
});

child.on('close', (code) => {
  console.log(`Cortex MCP server exited with code ${code}`);
  process.exit(code);
});