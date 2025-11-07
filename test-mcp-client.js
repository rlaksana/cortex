#!/usr/bin/env node

/**
 * MCP Client Simulation Test
 * Simulates how MCP clients (like Codex CLI) actually connect and handshake with MCP servers
 */

import { spawn } from 'child_process';
import { randomUUID } from 'crypto';

console.error('=== MCP Client Simulation Test ===');

// Test function to simulate full MCP client handshake
async function testMCPClient(serverPath) {
  return new Promise((resolve, reject) => {
    console.error('Starting MCP client simulation...');

    // Spawn the MCP server process
    const child = spawn('node', [serverPath], {
      stdio: ['pipe', 'pipe', 'pipe'], // All three streams as pipes
      env: {
        ...process.env,
        NODE_ENV: 'development',
        LOG_LEVEL: 'error',
      },
    });

    let responseData = '';
    let isHandshakeComplete = false;
    const requestId = randomUUID();

    // Timeout for entire test
    const timeout = setTimeout(() => {
      if (!isHandshakeComplete) {
        child.kill('SIGTERM');
        reject(new Error('MCP handshake timeout after 10 seconds'));
      }
    }, 10000);

    // Send initialize request
    const initializeRequest = {
      jsonrpc: '2.0',
      id: requestId,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {
          tools: {},
        },
        clientInfo: {
          name: 'test-mcp-client',
          version: '1.0.0',
        },
      },
    };

    console.error('Sending initialize request:', JSON.stringify(initializeRequest, null, 2));
    child.stdin.write(JSON.stringify(initializeRequest) + '\n');

    // Listen for responses
    child.stdout.on('data', (data) => {
      const chunk = data.toString();
      responseData += chunk;

      console.error('Received data chunk:', chunk);

      // Try to parse complete JSON-RPC response
      try {
        const lines = responseData.split('\n').filter((line) => line.trim());
        for (const line of lines) {
          if (line.startsWith('{') && line.endsWith('}')) {
            const response = JSON.parse(line);
            console.error('Parsed JSON-RPC response:', response);

            if (response.id === requestId) {
              if (response.result) {
                console.error('✅ MCP Handshake SUCCESS!');
                console.error('Response:', JSON.stringify(response.result, null, 2));
                isHandshakeComplete = true;
                clearTimeout(timeout);

                // Test tools list
                const toolsRequest = {
                  jsonrpc: '2.0',
                  id: randomUUID(),
                  method: 'tools/list',
                };

                console.error('Sending tools/list request...');
                child.stdin.write(JSON.stringify(toolsRequest) + '\n');

                // Close after a short delay
                setTimeout(() => {
                  child.kill('SIGTERM');
                  resolve({
                    success: true,
                    initializeResponse: response,
                    serverPath,
                  });
                }, 1000);
              } else if (response.error) {
                console.error('❌ MCP Handshake FAILED!');
                console.error('Error:', response.error);
                clearTimeout(timeout);
                child.kill('SIGTERM');
                reject(new Error(`MCP Error: ${response.error.message}`));
              }
            }
          }
        }
      } catch (e) {
        // Not complete JSON yet, continue accumulating
      }
    });

    child.stderr.on('data', (data) => {
      console.error('Server stderr:', data.toString());
    });

    child.on('error', (error) => {
      clearTimeout(timeout);
      console.error('❌ Child process error:', error);
      reject(error);
    });

    child.on('close', (code, signal) => {
      clearTimeout(timeout);
      if (!isHandshakeComplete) {
        console.error(`❌ Server closed before handshake. Code: ${code}, Signal: ${signal}`);
        reject(new Error(`Server closed before handshake. Code: ${code}, Signal: ${signal}`));
      }
    });

    // Handle process termination
    process.on('SIGINT', () => {
      console.error('Received SIGINT, terminating test...');
      child.kill('SIGTERM');
      clearTimeout(timeout);
      reject(new Error('Test interrupted'));
    });
  });
}

// Test with different server entry points
async function runTests() {
  const servers = [{ name: 'simple-mcp-server.js', path: './dist/simple-mcp-server.js' }];

  for (const server of servers) {
    console.error(`\n=== Testing ${server.name} ===`);
    try {
      const result = await testMCPClient(server.path);
      console.error(`✅ ${server.name}: SUCCESS`);
      console.error('Initialize response:', result.initializeResponse);
    } catch (error) {
      console.error(`❌ ${server.name}: FAILED`);
      console.error('Error:', error.message);
    }

    // Wait between tests
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }

  console.error('\n=== Test Complete ===');
  process.exit(0);
}

// Run the tests
runTests().catch((error) => {
  console.error('Test suite failed:', error);
  process.exit(1);
});
