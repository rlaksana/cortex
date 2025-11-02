/**
 * Test the minimal MCP server to verify logger fix
 */

import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('=== Testing Minimal MCP Server ===\n');

// Start the minimal MCP server
const server = spawn('node', [path.join(__dirname, 'minimal-mcp-server.mjs')], {
  stdio: ['pipe', 'pipe', 'pipe'],
  env: { ...process.env, MCP_TRANSPORT: 'stdio' },
});

let stdoutBuffer = '';
let stderrBuffer = '';
let serverStarted = false;

server.stdout.on('data', (data) => {
  const output = data.toString();
  stdoutBuffer += output;
  console.log('STDOUT:', output.trim());
});

server.stderr.on('data', (data) => {
  const output = data.toString();
  stderrBuffer += output;

  if (output.includes('Minimal MCP Server started successfully')) {
    serverStarted = true;
    console.log('✅ Server started successfully!');
  }

  console.log('STDERR:', output.trim());
});

server.on('error', (error) => {
  console.error('❌ Failed to start server:', error);
  process.exit(1);
});

// Send initialize request after server starts
setTimeout(() => {
  console.log('\n=== Sending Initialize Request ===');

  const initRequest = {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2024-11-05',
      capabilities: { roots: { listChanged: true } },
      clientInfo: {
        name: 'test-client',
        version: '1.0.0',
      },
    },
  };

  server.stdin.write(JSON.stringify(initRequest) + '\n');
}, 2000);

// Listen for response and send tools request
setTimeout(() => {
  console.log('\n=== Sending Tools List Request ===');

  const toolsRequest = {
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/list',
    params: {},
  };

  server.stdin.write(JSON.stringify(toolsRequest) + '\n');
}, 4000);

// Test the logger tool
setTimeout(() => {
  console.log('\n=== Testing Logger Tool ===');

  const toolRequest = {
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: {
      name: 'test_logger',
      arguments: {
        message: 'Hello from MCP client!',
      },
    },
  };

  server.stdin.write(JSON.stringify(toolRequest) + '\n');
}, 6000);

// Final results
setTimeout(() => {
  console.log('\n=== Final Test Results ===');
  console.log('Server started:', serverStarted ? 'YES ✅' : 'NO ❌');
  console.log('STDOUT received:', stdoutBuffer.length > 0 ? 'YES' : 'NO');
  console.log('STDERR received:', stderrBuffer.length > 0 ? 'YES' : 'NO');

  // Check if stdout contains valid JSON-RPC responses (good!)
  const hasValidJsonRpc = stdoutBuffer.includes('jsonrpc') && stdoutBuffer.includes('"result"');
  console.log('Valid JSON-RPC response in stdout:', hasValidJsonRpc ? 'YES ✅' : 'NO ❌');

  // Check if stderr contains structured logs (good!)
  const hasStructuredLogs = stderrBuffer.includes('"level"') && stderrBuffer.includes('"msg"');
  console.log('Structured logs in stderr:', hasStructuredLogs ? 'YES ✅' : 'NO ❌');

  // Check if stdout contains JSON logs (bad!)
  const hasJsonLogsInStdout = stdoutBuffer.includes('"level"') && stdoutBuffer.includes('"msg"');
  console.log('JSON logs in stdout (should be NO):', hasJsonLogsInStdout ? 'YES ❌' : 'NO ✅');

  console.log('\n=== Logger Fix Verification ===');
  if (hasValidJsonRpc && hasStructuredLogs && !hasJsonLogsInStdout) {
    console.log('🎉 SUCCESS: MCP-safe logger is working perfectly!');
    console.log('   ✅ JSON-RPC responses go to stdout');
    console.log('   ✅ Structured logs go to stderr');
    console.log('   ✅ No stdout contamination');
  } else {
    console.log('❌ FAILURE: Logger fix needs more work');
  }

  console.log('\n=== Test Complete ===');
  server.kill();
  process.exit(0);
}, 8000);
