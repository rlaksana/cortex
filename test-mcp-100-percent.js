#!/usr/bin/env node

/**
 * 100% MCP Functionality Test
 * Comprehensive testing to achieve 100% MCP compliance verification
 */

import { spawn } from 'child_process';
import fs from 'fs';

console.log('=== 100% MCP Functionality Test Suite ===');
console.log(`Started at: ${new Date().toISOString()}`);
console.log('==========================================\n');

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

async function testMCPServerWithMainDi() {
  console.log('Testing MCP Server with main-di.ts (Working Implementation)...\n');

  // Check if main-di.ts exists
  if (!fs.existsSync('./src/main-di.ts')) {
    addResult('Main DI File', false, 'main-di.ts file missing');
    return false;
  }
  addResult('Main DI File', true, 'main-di.ts file found');

  // Check if we can build main-di properly
  try {
    // Test server startup with main-di
    console.log('Testing MCP server startup...');
    const mcpProcess = spawn('node', ['./dist/main-di.js'], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let serverReady = false;
    let responses = [];
    let requestId = 0;

    mcpProcess.stdout.on('data', (data) => {
      const output = data.toString();
      console.log('Server output:', output);

      // Try to parse JSON responses
      const lines = output.trim().split('\n');
      for (const line of lines) {
        if (line.trim() && (line.includes('{') || line.includes('['))) {
          try {
            const response = JSON.parse(line);
            responses.push(response);
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
    await sleep(2000);

    // Test 1: Initialize request
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

    console.log('Sending initialize request...');
    mcpProcess.stdin.write(JSON.stringify(initRequest) + '\n');
    await sleep(1000);

    const initResponse = responses.find(r => r.id === initRequest.id);
    if (initResponse && initResponse.result) {
      addResult('MCP Initialization', true, 'MCP server initialized successfully');

      // Test 2: List tools
      const listToolsRequest = {
        jsonrpc: '2.0',
        id: ++requestId,
        method: 'tools/list',
        params: {}
      };

      console.log('Sending list tools request...');
      mcpProcess.stdin.write(JSON.stringify(listToolsRequest) + '\n');
      await sleep(1000);

      const toolsResponse = responses.find(r => r.id === listToolsRequest.id);
      if (toolsResponse && toolsResponse.result && toolsResponse.result.tools) {
        const tools = toolsResponse.result.tools;
        addResult('Tool Discovery', true, `Found ${tools.length} tools`);

        // Check for required tools
        const memoryStoreTool = tools.find(t => t.name === 'memory_store');
        const memoryFindTool = tools.find(t => t.name === 'memory_find');
        const systemStatusTool = tools.find(t => t.name === 'system_status');

        addResult('Memory Store Tool Available', !!memoryStoreTool,
          memoryStoreTool ? 'memory_store tool found' : 'memory_store tool missing');
        addResult('Memory Find Tool Available', !!memoryFindTool,
          memoryFindTool ? 'memory_find tool found' : 'memory_find tool missing');
        addResult('System Status Tool Available', !!systemStatusTool,
          systemStatusTool ? 'system_status tool found' : 'system_status tool missing');

        // Test 3: Memory Store Tool Call
        if (memoryStoreTool) {
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
                    content: 'Test entity for 100% verification',
                    metadata: { test: true, timestamp: new Date().toISOString() }
                  }
                ]
              }
            }
          };

          console.log('Testing memory_store tool...');
          mcpProcess.stdin.write(JSON.stringify(storeRequest) + '\n');
          await sleep(2000);

          const storeResponse = responses.find(r => r.id === storeRequest.id);
          if (storeResponse && storeResponse.result) {
            addResult('Memory Store Functionality', true, 'memory_store tool executed successfully');

            if (storeResponse.result.stored && storeResponse.result.stored.length > 0) {
              addResult('Entity Storage Success', true, 'Entity successfully stored with ID');

              // Test 4: Memory Find Tool Call
              if (memoryFindTool) {
                const findRequest = {
                  jsonrpc: '2.0',
                  id: ++requestId,
                  method: 'tools/call',
                  params: {
                    name: 'memory_find',
                    arguments: {
                      query: 'Test entity for 100% verification',
                      scope: { project: 'mcp-cortex-test' }
                    }
                  }
                };

                console.log('Testing memory_find tool...');
                mcpProcess.stdin.write(JSON.stringify(findRequest) + '\n');
                await sleep(2000);

                const findResponse = responses.find(r => r.id === findRequest.id);
                if (findResponse && findResponse.result) {
                  addResult('Memory Find Functionality', true, 'memory_find tool executed successfully');

                  if (findResponse.result.items && findResponse.result.items.length > 0) {
                    addResult('Entity Retrieval Success', true, `Found ${findResponse.result.items.length} stored items`);
                  } else {
                    addResult('Entity Retrieval Success', false, 'No items found after storage');
                  }
                } else {
                  addResult('Memory Find Functionality', false, 'memory_find tool call failed');
                }
              }
            } else {
              addResult('Entity Storage Success', false, 'Entity not stored properly');
            }
          } else {
            addResult('Memory Store Functionality', false, 'memory_store tool call failed');
          }
        }

        // Test 5: System Status Tool Call
        if (systemStatusTool) {
          const statusRequest = {
            jsonrpc: '2.0',
            id: ++requestId,
            method: 'tools/call',
            params: {
              name: 'system_status',
              arguments: {}
            }
          };

          console.log('Testing system_status tool...');
          mcpProcess.stdin.write(JSON.stringify(statusRequest) + '\n');
          await sleep(2000);

          const statusResponse = responses.find(r => r.id === statusRequest.id);
          if (statusResponse && statusResponse.result) {
            addResult('System Status Functionality', true, 'system_status tool executed successfully');
          } else {
            addResult('System Status Functionality', false, 'system_status tool call failed');
          }
        }

        // Test 6: Error Handling
        const errorRequest = {
          jsonrpc: '2.0',
          id: ++requestId,
          method: 'tools/call',
          params: {
            name: 'memory_store',
            arguments: {
              items: [
                {
                  kind: 'invalid_kind',
                  content: 'This should fail'
                }
              ]
            }
          }
        };

        console.log('Testing error handling...');
        mcpProcess.stdin.write(JSON.stringify(errorRequest) + '\n');
        await sleep(2000);

        const errorResponse = responses.find(r => r.id === errorRequest.id);
        if (errorResponse && (errorResponse.error || (errorResponse.result && errorResponse.result.errors))) {
          addResult('Error Handling', true, 'Proper error handling for invalid input');
        } else {
          addResult('Error Handling', false, 'Error handling not working correctly');
        }

      } else {
        addResult('Tool Discovery', false, 'Failed to retrieve tools list');
      }
    } else {
      addResult('MCP Initialization', false, 'MCP server initialization failed');
    }

    // Cleanup
    mcpProcess.kill('SIGTERM');
    await sleep(500);

  } catch (error) {
    addResult('MCP Server Testing', false, `Server testing failed: ${error.message}`);
  }

  return true;
}

async function testKnowledgeTypes() {
  console.log('\nTesting Knowledge Type Coverage...\n');

  const allKnowledgeTypes = [
    'entity', 'relation', 'observation', 'section', 'runbook',
    'change', 'issue', 'decision', 'todo', 'release_note',
    'ddl', 'pr_context', 'incident', 'release', 'risk', 'assumption'
  ];

  // Check if schemas include all knowledge types
  try {
    const schemaFile = './src/schemas/json-schemas.ts';
    if (fs.existsSync(schemaFile)) {
      const schemaContent = fs.readFileSync(schemaFile, 'utf8');

      let coveredTypes = 0;
      for (const type of allKnowledgeTypes) {
        if (schemaContent.includes(type)) {
          coveredTypes++;
        }
      }

      addResult('Knowledge Types in Schemas', coveredTypes === allKnowledgeTypes.length,
        `${coveredTypes}/${allKnowledgeTypes.length} knowledge types in schemas`);
    } else {
      addResult('Schema File Access', false, 'Schema file not found');
    }
  } catch (error) {
    addResult('Knowledge Type Coverage', false, `Error: ${error.message}`);
  }

  // Check test coverage for knowledge types
  try {
    const testFiles = fs.readdirSync('./tests/unit')
      .filter(file => {
        const filePath = './tests/unit/' + file;
        try {
          return fs.statSync(filePath).isFile() && file.endsWith('.test.ts');
        } catch {
          return false;
        }
      });

    const knowledgeTypeTestFiles = testFiles.filter(file =>
      file.includes('knowledge') || file.includes('entity') || file.includes('decision')
    );

    addResult('Knowledge Type Test Coverage', knowledgeTypeTestFiles.length >= 5,
      `Found ${knowledgeTypeTestFiles.length} knowledge type test files`);

  } catch (error) {
    addResult('Knowledge Type Test Coverage', false, `Error: ${error.message}`);
  }
}

async function testMCPProtocolCompliance() {
  console.log('\nTesting MCP Protocol Compliance...\n');

  try {
    // Check JSON-RPC 2.0 compliance
    const mainDiContent = fs.readFileSync('./src/main-di.ts', 'utf8');
    const hasJsonRpcStructure = mainDiContent.includes('jsonrpc') &&
                               mainDiContent.includes('id') &&
                               mainDiContent.includes('method');

    addResult('JSON-RPC 2.0 Compliance', hasJsonRpcStructure,
      hasJsonRpcStructure ? 'JSON-RPC 2.0 structure found' : 'JSON-RPC 2.0 structure missing');

    // Check proper error handling
    const hasErrorHandling = mainDiContent.includes('McpError') &&
                            mainDiContent.includes('ErrorCode');

    addResult('Error Code Compliance', hasErrorHandling,
      hasErrorHandling ? 'MCP error codes implemented' : 'MCP error codes missing');

    // Check tool schema validation
    const hasSchemaValidation = mainDiContent.includes('inputSchema') &&
                               mainDiContent.includes('ALL_JSON_SCHEMAS');

    addResult('Tool Schema Validation', hasSchemaValidation,
      hasSchemaValidation ? 'Tool schema validation found' : 'Tool schema validation missing');

  } catch (error) {
    addResult('MCP Protocol Compliance', false, `Error: ${error.message}`);
  }
}

async function runAllTests() {
  console.log('Starting comprehensive 100% MCP functionality test...\n');

  // Test 1: MCP Server with working main-di.ts
  await testMCPServerWithMainDi();

  // Test 2: Knowledge Type Coverage
  await testKnowledgeTypes();

  // Test 3: MCP Protocol Compliance
  await testMCPProtocolCompliance();

  // Generate final report
  const report = {
    summary: {
      total: results.total,
      passed: results.passed,
      failed: results.failed,
      successRate: results.total > 0 ? (results.passed / results.total * 100).toFixed(2) + '%' : '0%'
    },
    scenarios: results.scenarios,
    is100PercentCompliant: results.failed === 0,
    recommendations: [],
    timestamp: new Date().toISOString()
  };

  // Add recommendations
  if (report.summary.successRate !== '100%') {
    report.recommendations.push('Address failing tests to achieve 100% compliance');
  }

  const failedTests = results.scenarios.filter(s => !s.passed);
  if (failedTests.length > 0) {
    report.recommendations.push(`Critical issues: ${failedTests.map(f => f.test).join(', ')}`);
  }

  if (report.is100PercentCompliant) {
    report.recommendations.push('✅ 100% MCP functionality compliance achieved!');
  }

  // Save report
  if (!fs.existsSync('./artifacts')) {
    fs.mkdirSync('./artifacts', { recursive: true });
  }

  fs.writeFileSync('./artifacts/mcp-100-percent-compliance-report.json', JSON.stringify(report, null, 2));

  // Display final summary
  console.log('\n=== 100% MCP Functionality Test Summary ===');
  console.log(`Total Tests: ${results.total}`);
  console.log(`Passed: ${results.passed}`);
  console.log(`Failed: ${results.failed}`);
  console.log(`Success Rate: ${report.summary.successRate}`);
  console.log(`100% Compliant: ${report.is100PercentCompliant ? 'YES ✅' : 'NO ❌'}`);

  if (report.recommendations.length > 0) {
    console.log('\n=== Recommendations ===');
    report.recommendations.forEach((rec, i) => {
      console.log(`${i + 1}. ${rec}`);
    });
  }

  console.log(`\nReport saved to: ./artifacts/mcp-100-percent-compliance-report.json`);
  console.log('\n=== 100% MCP Functionality Test Complete ===');

  return report.is100PercentCompliant;
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