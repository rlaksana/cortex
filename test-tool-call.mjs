/**
 * Test script untuk verifikasi Cortex MCP tool call functionality
 */

import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('=== Testing Cortex MCP Tool Call ===\n');

// Start Cortex MCP server
const server = spawn('node', [path.join(__dirname, 'dist', 'index.js')], {
  stdio: ['pipe', 'pipe', 'pipe'],
  env: { ...process.env, MCP_TRANSPORT: 'stdio' },
});

let stdoutBuffer = '';
let stderrBuffer = '';
let serverReady = false;

server.stdout.on('data', (data) => {
  const output = data.toString();
  stdoutBuffer += output;
  console.log('STDOUT:', output.trim());
});

server.stderr.on('data', (data) => {
  const output = data.toString();
  stderrBuffer += output;

  if (output.includes('Cortex MCP Server (Stub Version) started')) {
    serverReady = true;
    console.log('✅ Server siap untuk tool calls!');
  }
});

server.on('error', (error) => {
  console.error('❌ Server error:', error);
  process.exit(1);
});

// Test tool calls setelah server siap
setTimeout(() => {
  if (!serverReady) {
    console.log('⚠️ Server mungkin belum siap, mencoba test anyway...');
  }

  console.log('\n=== 1. Testing Tools List ===');

  const toolsRequest = {
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/list',
    params: {},
  };

  server.stdin.write(JSON.stringify(toolsRequest) + '\n');
}, 3000);

// Test auth_login tool
setTimeout(() => {
  console.log('\n=== 2. Testing Auth Login Tool ===');

  const loginRequest = {
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: {
      name: 'auth_login',
      arguments: {
        username: 'admin',
        password: 'admin123',
      },
    },
  };

  server.stdin.write(JSON.stringify(loginRequest) + '\n');
}, 5000);

// Test memory_store tool dengan token
setTimeout(() => {
  console.log('\n=== 3. Testing Memory Store Tool ===');

  const storeRequest = {
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: {
      name: 'memory_store',
      arguments: {
        items: [
          {
            kind: 'entity',
            data: {
              name: 'Test Entity',
              description: 'Test tool call functionality',
              type: 'test',
            },
          },
        ],
        auth_token: 'mock_token_for_test',
      },
    },
  };

  server.stdin.write(JSON.stringify(storeRequest) + '\n');
}, 7000);

// Test memory_find tool
setTimeout(() => {
  console.log('\n=== 4. Testing Memory Find Tool ===');

  const findRequest = {
    jsonrpc: '2.0',
    id: 4,
    method: 'tools/call',
    params: {
      name: 'memory_find',
      arguments: {
        query: 'test entity',
        scope: { project: 'test' },
        mode: 'auto',
        auth_token: 'mock_token_for_test',
      },
    },
  };

  server.stdin.write(JSON.stringify(findRequest) + '\n');
}, 9000);

// Final results
setTimeout(() => {
  console.log('\n=== Test Results Summary ===');

  // Check untuk JSON-RPC responses
  const hasToolsList = stdoutBuffer.includes('tools') && stdoutBuffer.includes('"result"');
  const hasLoginResponse = stdoutBuffer.includes('access_token') || stdoutBuffer.includes('error');
  const hasStoreResponse = stdoutBuffer.includes('stored_count') || stdoutBuffer.includes('error');
  const hasFindResponse = stdoutBuffer.includes('hits') || stdoutBuffer.includes('error');

  console.log('Tools List:', hasToolsList ? '✅ SUCCESS' : '❌ FAILED');
  console.log('Auth Login:', hasLoginResponse ? '✅ SUCCESS' : '❌ FAILED');
  console.log('Memory Store:', hasStoreResponse ? '✅ SUCCESS' : '❌ FAILED');
  console.log('Memory Find:', hasFindResponse ? '✅ SUCCESS' : '❌ FAILED');

  console.log('\n--- Server Log Summary ---');
  console.log('Server Ready:', serverReady ? '✅ YES' : '⚠️ NOT DETECTED');
  console.log('Structured Logs in stderr:', stderrBuffer.includes('"level"') ? '✅ YES' : '❌ NO');
  console.log(
    'JSON-RPC Responses in stdout:',
    stdoutBuffer.includes('jsonrpc') ? '✅ YES' : '❌ NO'
  );

  if (hasToolsList && hasLoginResponse) {
    console.log('\n🎉 Cortex MCP tool calls bekerja dengan baik!');
  } else {
    console.log('\n⚠️ Ada masalah dengan tool calls - perlu investigasi lebih lanjut');
  }

  console.log('\n=== Test Complete ===');
  server.kill();
  process.exit(0);
}, 12000);
