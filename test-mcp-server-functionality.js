#!/usr/bin/env node

/**
 * MCP Server Functionality Test
 * Tests the actual MCP server with tool calls
 */

import { spawn } from 'child_process';
import fs from 'fs';

console.log('=== MCP Server Functionality Test ===');
console.log(`Started at: ${new Date().toISOString()}`);
console.log('=====================================\n');

const results = {
  total: 0,
  passed: 0,
  failed: 0,
  scenarios: []
};

function addResult(test, passed, message, details = null) {
  results.total++;
  if (passed) results.passed++;
  else results.failed++;

  const result = {
    test,
    passed,
    message,
    details,
    timestamp: new Date().toISOString()
  };
  results.scenarios.push(result);

  console.log(`${passed ? '✓' : '✗'} [${passed ? 'PASS' : 'FAIL'}] ${test}: ${message}`);
  if (details && !passed) {
    console.log(`  Details: ${JSON.stringify(details, null, 2)}`);
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function testMcpServer() {
  console.log('Testing MCP Server Tool Calls...\n');

  // Check if dist/index.js exists
  if (!fs.existsSync('./dist/index.js')) {
    addResult('MCP Server Build', false, 'MCP server not built - dist/index.js missing');
    return false;
  }
  addResult('MCP Server Build', true, 'MCP server built successfully');

  let mcpProcess = null;
  let requestId = 0;

  try {
    // Start MCP server
    console.log('Starting MCP server...');
    mcpProcess = spawn('node', ['./dist/index.js'], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let serverReady = false;
    let serverOutput = '';
    const responses = [];

    // Set up response handling
    mcpProcess.stdout.on('data', (data) => {
      const output = data.toString();
      serverOutput += output;

      // Try to parse JSON responses
      const lines = output.trim().split('\n');
      for (const line of lines) {
        if (line.trim() && (line.includes('{') || line.includes('['))) {
          try {
            const response = JSON.parse(line);
            responses.push(response);
            console.log('Server response:', JSON.stringify(response, null, 2));
          } catch (e) {
            // Not JSON, continue
          }
        }
      }
    });

    mcpProcess.stderr.on('data', (data) => {
      console.log('Server stderr:', data.toString());
    });

    mcpProcess.on('error', (error) => {
      console.error('MCP Server error:', error);
    });

    // Wait for server to initialize
    await sleep(3000);

    // Send initialization request
    const initRequest = {
      jsonrpc: '2.0',
      id: ++requestId,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        clientInfo: { name: 'test-client', version: '1.0.0' }
      }
    };

    console.log('Sending initialization request...');
    mcpProcess.stdin.write(JSON.stringify(initRequest) + '\n');
    await sleep(2000);

    // Send list tools request
    const listToolsRequest = {
      jsonrpc: '2.0',
      id: ++requestId,
      method: 'tools/list',
      params: {}
    };

    console.log('Sending list tools request...');
    mcpProcess.stdin.write(JSON.stringify(listToolsRequest) + '\n');
    await sleep(2000);

    // Check for tools response
    const toolsResponse = responses.find(r => r.id === listToolsRequest.id);
    if (toolsResponse && toolsResponse.result && toolsResponse.result.tools) {
      const tools = toolsResponse.result.tools;
      addResult('Tools List Retrieved', true, `Found ${tools.length} tools`);

      // Check for expected tools
      const hasMemoryStore = tools.some(t => t.name === 'memory_store');
      const hasMemoryFind = tools.some(t => t.name === 'memory_find');

      addResult('Memory Store Tool Available', hasMemoryStore,
        hasMemoryStore ? 'memory_store tool found' : 'memory_store tool missing');
      addResult('Memory Find Tool Available', hasMemoryFind,
        hasMemoryFind ? 'memory_find tool found' : 'memory_find tool missing');

      // Test memory_store tool call if available
      if (hasMemoryStore) {
        const storeRequest = {
          jsonrpc: '2.0',
          id: ++requestId,
          method: 'tools/call',
          params: {
            name: 'memory_store',
            arguments: {
              items: [
                {
                  kind: 'entity',
                  content: 'Test entity from server test',
                  metadata: { test: true, timestamp: new Date().toISOString() }
                }
              ]
            }
          }
        };

        console.log('Testing memory_store tool...');
        mcpProcess.stdin.write(JSON.stringify(storeRequest) + '\n');
        await sleep(3000);

        const storeResponse = responses.find(r => r.id === storeRequest.id);
        if (storeResponse && storeResponse.result) {
          addResult('Memory Store Tool Call', true, 'memory_store tool executed successfully');

          if (storeResponse.result.stored && storeResponse.result.stored.length > 0) {
            addResult('Entity Storage', true, 'Entity successfully stored');
          } else {
            addResult('Entity Storage', false, 'Entity not stored properly', storeResponse.result);
          }
        } else {
          addResult('Memory Store Tool Call', false, 'memory_store tool call failed', storeResponse);
        }
      }

      // Test memory_find tool call if available
      if (hasMemoryFind) {
        const findRequest = {
          jsonrpc: '2.0',
          id: ++requestId,
          method: 'tools/call',
          params: {
            name: 'memory_find',
            arguments: {
              query: 'test entity',
              scope: { project: 'mcp-cortex-test' }
            }
          }
        };

        console.log('Testing memory_find tool...');
        mcpProcess.stdin.write(JSON.stringify(findRequest) + '\n');
        await sleep(3000);

        const findResponse = responses.find(r => r.id === findRequest.id);
        if (findResponse && findResponse.result) {
          addResult('Memory Find Tool Call', true, 'memory_find tool executed successfully');

          if (findResponse.result.items && findResponse.result.items.length > 0) {
            addResult('Entity Retrieval', true, `Found ${findResponse.result.items.length} items`);
          } else {
            addResult('Entity Retrieval', false, 'No items found', findResponse.result);
          }
        } else {
          addResult('Memory Find Tool Call', false, 'memory_find tool call failed', findResponse);
        }
      }

    } else {
      addResult('Tools List Retrieved', false, 'Failed to retrieve tools list', toolsResponse);
    }

  } catch (error) {
    addResult('MCP Server Test', false, `MCP server test failed: ${error.message}`);
  } finally {
    // Clean up
    if (mcpProcess) {
      console.log('Stopping MCP server...');
      mcpProcess.kill('SIGTERM');
      mcpProcess = null;
    }
  }

  return true;
}

async function runAllTests() {
  // Test MCP server functionality
  await testMcpServer();

  // Generate final report
  const report = {
    summary: {
      total: results.total,
      passed: results.passed,
      failed: results.failed,
      successRate: results.total > 0 ? (results.passed / results.total * 100).toFixed(2) + '%' : '0%'
    },
    scenarios: results.scenarios,
    recommendations: [],
    timestamp: new Date().toISOString()
  };

  // Add recommendations
  if (report.summary.successRate !== '100%') {
    report.recommendations.push('Fix failing MCP server tests');
  }

  const failedTests = results.scenarios.filter(s => !s.passed);
  if (failedTests.length > 0) {
    report.recommendations.push(`Priority issues: ${failedTests.map(f => f.test).join(', ')}`);
  }

  if (results.passed / results.total >= 0.8) {
    report.recommendations.push('MCP server functionality is working correctly');
  }

  // Save report
  if (!fs.existsSync('./artifacts')) {
    fs.mkdirSync('./artifacts', { recursive: true });
  }

  fs.writeFileSync('./artifacts/mcp-server-functionality-report.json', JSON.stringify(report, null, 2));

  // Display final summary
  console.log('\n=== MCP Server Test Summary ===');
  console.log(`Total Tests: ${results.total}`);
  console.log(`Passed: ${results.passed}`);
  console.log(`Failed: ${results.failed}`);
  console.log(`Success Rate: ${report.summary.successRate}`);

  if (report.recommendations.length > 0) {
    console.log('\n=== Recommendations ===');
    report.recommendations.forEach((rec, i) => {
      console.log(`${i + 1}. ${rec}`);
    });
  }

  console.log(`\nReport saved to: ./artifacts/mcp-server-functionality-report.json`);
  console.log('\n=== MCP Server Test Complete ===');

  return report.summary.successRate === '100%';
}

// Run tests
runAllTests()
  .then(success => {
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    console.error('Test execution failed:', error);
    process.exit(1);
  });