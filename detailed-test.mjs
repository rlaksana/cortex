/**
 * Detailed MCP test script to debug server communication
 */

import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('=== Detailed MCP Cortex Server Test ===\n');

// Start the MCP server
const server = spawn('node', [path.join(__dirname, 'dist', 'index.js')], {
  stdio: ['pipe', 'pipe', 'pipe'], // pipe stdin, stdout, stderr
  env: { ...process.env, MCP_TRANSPORT: 'stdio' }
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

  // Check for server start message
  if (output.includes('Cortex MCP Server (Stub Version) started')) {
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
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
      capabilities: {
        roots: { listChanged: true },
        sampling: {}
      },
      clientInfo: {
        name: "test-client",
        version: "1.0.0"
      }
    }
  };

  console.log('Sending:', JSON.stringify(initRequest, null, 2));
  server.stdin.write(JSON.stringify(initRequest) + '\n');

}, 3000);

// Listen for initialize response
setTimeout(() => {
  console.log('\n=== Checking for Initialize Response ===');

  if (stdoutBuffer.includes('jsonrpc') && stdoutBuffer.includes('"result"')) {
    console.log('✅ Received valid JSON-RPC response');

    // Extract and parse the response
    const lines = stdoutBuffer.split('\n').filter(line => line.trim().startsWith('{'));
    if (lines.length > 0) {
      try {
        const response = JSON.parse(lines[0]);
        console.log('Response:', JSON.stringify(response, null, 2));
      } catch (e) {
        console.log('Could not parse response as JSON');
      }
    }
  } else {
    console.log('❌ No valid JSON-RPC response received');
    console.log('STDOUT buffer content:', stdoutBuffer);
  }

  // Send tools/list request
  console.log('\n=== Sending Tools List Request ===');

  const toolsRequest = {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/list",
    params: {}
  };

  console.log('Sending:', JSON.stringify(toolsRequest, null, 2));
  server.stdin.write(JSON.stringify(toolsRequest) + '\n');

}, 5000);

// Final check
setTimeout(() => {
  console.log('\n=== Final Test Results ===');
  console.log('Server started:', serverStarted ? 'YES ✅' : 'NO ❌');
  console.log('STDOUT received:', stdoutBuffer.length > 0 ? 'YES' : 'NO');
  console.log('STDERR received:', stderrBuffer.length > 0 ? 'YES' : 'NO');
  console.log('Structured logs in stderr:', stderrBuffer.includes('"level"') && stderrBuffer.includes('"msg"') ? 'YES ✅' : 'NO');
  console.log('Server start message in stderr:', stderrBuffer.includes('Cortex MCP Server (Stub Version) started') ? 'YES ✅' : 'NO ❌');

  // Check if stdout contains only dotenv message (good) or JSON logs (bad)
  const hasJsonLogsInStdout = stdoutBuffer.includes('"level"') && stdoutBuffer.includes('"msg"');
  console.log('JSON logs in stdout (should be NO):', hasJsonLogsInStdout ? 'YES ❌' : 'NO ✅');

  if (stderrBuffer.length > 0) {
    console.log('\n=== Sample STDERR Content ===');
    const stderrLines = stderrBuffer.split('\n').filter(line => line.trim());
    console.log('First 3 lines of stderr:');
    stderrLines.slice(0, 3).forEach((line, i) => console.log(`${i+1}: ${line}`));
  }

  console.log('\n=== Test Complete ===');
  server.kill();
  process.exit(0);
}, 8000);