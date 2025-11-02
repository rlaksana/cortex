/**
 * Simple MCP test script to verify server functionality
 */

import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('Testing MCP Cortex Server...\n');

// Start the MCP server
const server = spawn('node', [path.join(__dirname, 'dist', 'index.js')], {
  stdio: ['pipe', 'pipe', 'pipe'], // pipe stdin, stdout, stderr
  env: { ...process.env, MCP_TRANSPORT: 'stdio' },
});

let stdoutBuffer = '';
let stderrBuffer = '';

server.stdout.on('data', (data) => {
  stdoutBuffer += data.toString();
  console.log('STDOUT:', data.toString().trim());
});

server.stderr.on('data', (data) => {
  stderrBuffer += data.toString();
  // Don't log stderr as it contains our JSON logs
});

server.on('error', (error) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});

setTimeout(() => {
  console.log('\n--- Sending MCP Initialize Request ---');

  // Send a proper JSON-RPC initialize request
  const initRequest = {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2024-11-05',
      capabilities: {
        roots: {
          listChanged: true,
        },
        sampling: {},
      },
      clientInfo: {
        name: 'test-client',
        version: '1.0.0',
      },
    },
  };

  server.stdin.write(JSON.stringify(initRequest) + '\n');

  // Wait for response
  setTimeout(() => {
    console.log('\n--- Sending Tools List Request ---');

    const toolsRequest = {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/list',
      params: {},
    };

    server.stdin.write(JSON.stringify(toolsRequest) + '\n');

    // Wait for response and then check results
    setTimeout(() => {
      console.log('\n--- Test Results ---');
      console.log('STDOUT received:', stdoutBuffer.length > 0 ? 'YES' : 'NO');
      console.log('STDERR received:', stderrBuffer.length > 0 ? 'YES' : 'NO');

      // Check if stdout contains valid JSON-RPC responses (not just logs)
      const hasValidJsonRpc = stdoutBuffer.includes('jsonrpc') && stdoutBuffer.includes('"result"');
      console.log('Valid JSON-RPC response:', hasValidJsonRpc ? 'YES' : 'NO');

      // Check if stderr contains structured JSON logs (which is what we want)
      const hasStructuredLogs = stderrBuffer.includes('"level"') && stderrBuffer.includes('"msg"');
      console.log('Structured logs in stderr:', hasStructuredLogs ? 'YES' : 'NO');

      console.log('\n--- Test Complete ---');

      server.kill();
      process.exit(0);
    }, 3000);
  }, 2000);
}, 2000);
