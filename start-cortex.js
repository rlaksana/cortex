#!/usr/bin/env node

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { createConnection } from 'net';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🚀 Starting Cortex MCP Server...');

// Check if PostgreSQL is running by attempting to connect to the port
function checkPostgresConnection() {
  const socket = createConnection({ host: 'localhost', port: 5433 });

  const timeout = setTimeout(() => {
    socket.destroy();
    console.error('❌ PostgreSQL connection timeout - port 5433 is not responding');
    console.error('Please start PostgreSQL Docker container first');
    console.error('Run: docker compose up -d postgres');
    process.exit(1);
  }, 5000);

  socket.on('connect', () => {
    clearTimeout(timeout);
    socket.destroy();
    console.log('✅ PostgreSQL is running on port 5433');
    startCortexServer();
  });

  socket.on('error', (error) => {
    clearTimeout(timeout);
    socket.destroy();
    console.error('❌ PostgreSQL is not running on port 5433');
    console.error('Please start PostgreSQL Docker container first');
    console.error('Run: docker compose up -d postgres');
    process.exit(1);
  });
}

checkPostgresConnection();

function startCortexServer() {
  const cortexProcess = spawn('node', ['dist/index.js'], {
    cwd: __dirname,
    stdio: 'inherit'
  });

  cortexProcess.on('error', (error) => {
    console.error('❌ Failed to start Cortex MCP server:', error.message);
    process.exit(1);
  });

  cortexProcess.on('exit', (code) => {
    if (code !== 0) {
      console.error(`❌ Cortex MCP server exited with code ${code}`);
      process.exit(code);
    }
  });

  // Handle graceful shutdown
  process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down Cortex MCP server...');
    cortexProcess.kill('SIGINT');
  });

  process.on('SIGTERM', () => {
    console.log('\n🛑 Shutting down Cortex MCP server...');
    cortexProcess.kill('SIGTERM');
  });
}