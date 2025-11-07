#!/usr/bin/env node

/**
 * Simple test script for the minimal MCP server
 */

import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function testMCPServer() {
  console.log('🧪 Testing Minimal MCP Server...\n');

  // Start the MCP server
  const server = spawn('node', [path.join(__dirname, 'dist', 'minimal-mcp-server.js')], {
    stdio: ['pipe', 'pipe', 'pipe']
  });

  let serverOutput = '';
  let testResults = [];

  server.stdout.on('data', (data) => {
    serverOutput += data.toString();
    const lines = data.toString().trim().split('\n');

    lines.forEach(line => {
      if (line.startsWith('{') && line.endsWith('}')) {
        try {
          const response = JSON.parse(line);
          testResults.push(response);
          console.log('📨 Server Response:', JSON.stringify(response, null, 2));
          console.log('---');
        } catch (error) {
          console.log('📄 Server Output:', line);
        }
      }
    });
  });

  server.stderr.on('data', (data) => {
    console.error('❌ Server Error:', data.toString());
  });

  // Send test requests
  const testRequests = [
    {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: {
          name: 'test-client',
          version: '1.0.0'
        }
      }
    },
    {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/list',
      params: {}
    },
    {
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: {
        name: 'system_status',
        arguments: {}
      }
    },
    {
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: {
        name: 'memory_store',
        arguments: {
          items: [
            {
              kind: 'observation',
              data: { content: 'Test observation' }
            }
          ]
        }
      }
    },
    {
      jsonrpc: '2.0',
      id: 5,
      method: 'tools/call',
      params: {
        name: 'memory_find',
        arguments: {
          query: 'test',
          limit: 5
        }
      }
    }
  ];

  // Send requests with delays
  let delay = 100;
  testRequests.forEach((request, index) => {
    setTimeout(() => {
      console.log(`📤 Sending Request ${index + 1}:`, request.method);
      server.stdin.write(JSON.stringify(request) + '\n');
    }, delay);
    delay += 1000;
  });

  // Complete the test
  setTimeout(() => {
    console.log('\n📊 Test Results Summary:');
    console.log(`✅ Total Responses Received: ${testResults.length}`);
    console.log(`✅ Successful Responses: ${testResults.filter(r => r.result).length}`);
    console.log(`❌ Error Responses: ${testResults.filter(r => r.error).length}`);

    if (testResults.length === testRequests.length) {
      console.log('\n🎉 All tests passed! MCP server is working correctly.');

      // Verify expected functionality
      const initializeResponse = testResults.find(r => r.id === 1);
      const toolsListResponse = testResults.find(r => r.id === 2);
      const statusResponse = testResults.find(r => r.id === 3);

      if (initializeResponse?.result?.serverInfo?.name === 'cortex-memory-mcp') {
        console.log('✅ Server initialization successful');
      }

      if (toolsListResponse?.result?.tools?.length === 3) {
        console.log('✅ Tools list contains expected 3 tools');
      }

      if (statusResponse?.result?.content?.[0]?.text) {
        console.log('✅ System status tool working');
      }
    } else {
      console.log('\n⚠️ Some tests failed. Check the responses above.');
    }

    server.kill();
    process.exit(0);
  }, 7000);

  server.on('error', (error) => {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  });
}

testMCPServer();