#!/usr/bin/env node

/**
 * Test script to simulate Codex CLI MCP handshake
 * This simulates exactly how Codex CLI would initialize the MCP server
 */

import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('🧪 Testing MCP Server with Codex CLI Simulation...\n');

// Server configuration
const serverPath = path.join(__dirname, 'dist', 'index.js');
const _serverArgs = [];

// Environment variables (simulate Codex CLI)
const serverEnv = {
  ...process.env,
  NODE_ENV: 'development',
  LOG_LEVEL: 'info',
  SystemRoot: 'C:\\Windows',
  // Add any other environment variables that Codex CLI might set
};

console.log('📋 Server Configuration:');
console.log(`   Command: node ${serverPath}`);
console.log(`   Working Directory: ${process.cwd()}`);
console.log(`   Environment: development`);
console.log('');

// Start the MCP server
const server = spawn('node', [serverPath], {
  stdio: ['pipe', 'pipe', 'inherit'], // stdin=pipe, stdout=pipe, stderr=inherit
  env: serverEnv,
  cwd: process.cwd(),
});

let responseBuffer = '';
let testPassed = true;

// Handle server responses
server.stdout.on('data', (data) => {
  const response = data.toString();
  responseBuffer += response;

  try {
    // Parse JSON-RPC responses
    const lines = response.split('\n').filter((line) => line.trim());
    lines.forEach((line) => {
      if (line.startsWith('{') && line.endsWith('}')) {
        const jsonRpcResponse = JSON.parse(line);
        console.log('📨 Server Response:', JSON.stringify(jsonRpcResponse, null, 2));
      }
    });
  } catch {
    console.log('📝 Server Output:', response);
  }
});

// Handle server errors
server.on('error', (error) => {
  console.error('❌ Server Error:', error);
  testPassed = false;
});

// Handle server exit
server.on('close', (code) => {
  if (code === 0) {
    console.log('\n✅ Server exited successfully');
  } else {
    console.log(`\n❌ Server exited with code ${code}`);
    testPassed = false;
  }

  console.log('\n🏁 Test Results:');
  console.log(`   Status: ${testPassed ? '✅ PASSED' : '❌ FAILED'}`);
  console.log(
    `   MCP Handshake: ${responseBuffer.includes('protocolVersion') ? '✅ Success' : '❌ Failed'}`
  );
  console.log(
    `   Server Ready: ${responseBuffer.includes('serverInfo') ? '✅ Success' : '❌ Failed'}`
  );

  process.exit(testPassed ? 0 : 1);
});

// Send MCP initialize request (simulating Codex CLI)
console.log('🚀 Sending MCP Initialize Request...');
const initializeRequest = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2024-11-05',
    capabilities: {
      tools: {},
    },
    clientInfo: {
      name: 'codex-cli',
      version: '1.0.0',
    },
  },
};

server.stdin.write(JSON.stringify(initializeRequest) + '\n');

// Wait a moment then send a tools/list request
setTimeout(() => {
  console.log('🔧 Sending Tools List Request...');
  const toolsListRequest = {
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/list',
    params: {},
  };

  server.stdin.write(JSON.stringify(toolsListRequest) + '\n');
}, 1000);

// Wait another moment then send a tool call
setTimeout(() => {
  console.log('🔧 Sending Database Health Tool Call...');
  const toolCallRequest = {
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: {
      name: 'database_health',
      arguments: {},
    },
  };

  server.stdin.write(JSON.stringify(toolCallRequest) + '\n');
}, 2000);

// Wait and then gracefully shutdown
setTimeout(() => {
  console.log('🛑 Sending Shutdown Request...');
  const shutdownRequest = {
    jsonrpc: '2.0',
    id: 4,
    method: 'shutdown',
    params: {},
  };

  server.stdin.write(JSON.stringify(shutdownRequest) + '\n');
}, 3000);

// Force exit if server doesn't shut down gracefully
setTimeout(() => {
  console.log('⏰ Timeout reached, forcing exit...');
  server.kill('SIGTERM');
}, 5000);
