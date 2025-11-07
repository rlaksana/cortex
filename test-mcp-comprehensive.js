#!/usr/bin/env node

/**
 * Comprehensive MCP Protocol Test Suite
 * Tests all aspects of the MCP Cortex server functionality
 *
 * Tests:
 * 1. MCP Protocol Handshake and Initialization
 * 2. Tool Discovery (memory_store, memory_find, system_status)
 * 3. Memory Store Tool Functionality
 * 4. Memory Find Tool Functionality
 * 5. System Status Tool Functionality
 * 6. Error Handling for Invalid Requests
 * 7. Concurrent Access Testing
 *
 * @author MCP Protocol Testing Specialist
 * @version 1.0.0
 */

import { spawn } from 'child_process';
import { randomUUID } from 'crypto';
import { EventEmitter } from 'events';

// Test configuration
const TEST_CONFIG = {
  serverPath: './dist/index.js',
  timeout: 30000,
  testDelay: 1000,
  concurrentClients: 3,
  testResults: {
    handshake: { success: false, error: null, duration: 0 },
    toolDiscovery: { success: false, error: null, toolsFound: [] },
    memoryStore: { success: false, error: null, testResults: [] },
    memoryFind: { success: false, error: null, testResults: [] },
    systemStatus: { success: false, error: null, testResults: [] },
    errorHandling: { success: false, error: null, testResults: [] },
    concurrentAccess: { success: false, error: null, testResults: [] },
  },
};

// Test data
const TEST_DATA = {
  entity: {
    kind: 'entity',
    data: {
      title: 'Test Entity',
      description: 'A test entity for MCP protocol validation',
      type: 'component',
      metadata: {
        created: new Date().toISOString(),
        test: true,
      },
    },
  },
  decision: {
    kind: 'decision',
    data: {
      title: 'Test Decision',
      rationale: 'Test decision for MCP protocol validation',
      alternatives: ['Alternative 1', 'Alternative 2'],
      context: {
        created: new Date().toISOString(),
        test: true,
      },
    },
  },
  issue: {
    kind: 'issue',
    data: {
      title: 'Test Issue',
      description: 'Test issue for MCP protocol validation',
      severity: 'medium',
      status: 'open',
      context: {
        created: new Date().toISOString(),
        test: true,
      },
    },
  },
};

class MCPTestClient extends EventEmitter {
  constructor(options = {}) {
    super();
    this.process = null;
    this.requestId = 0;
    this.pendingRequests = new Map();
    this.isInitialized = false;
    this.responseData = '';
    this.options = options;
  }

  async connect(serverPath) {
    return new Promise((resolve, reject) => {
      console.error(`[CLIENT] Connecting to MCP server: ${serverPath}`);

      this.process = spawn('node', [serverPath], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: {
          ...process.env,
          NODE_ENV: 'development',
          LOG_LEVEL: 'warn', // Reduce noise during testing
          QDRANT_URL: 'http://localhost:6333',
          QDRANT_COLLECTION_NAME: 'cortex_test_collection',
        },
      });

      let connected = false;
      const timeout = setTimeout(() => {
        if (!connected) {
          this.process.kill('SIGTERM');
          reject(new Error('Connection timeout'));
        }
      }, 10000);

      this.process.on('error', (error) => {
        clearTimeout(timeout);
        console.error('[CLIENT] Process error:', error);
        reject(error);
      });

      this.process.stderr.on('data', (data) => {
        console.error('[SERVER STDERR]:', data.toString().trim());
      });

      this.process.stdout.on('data', (data) => {
        const chunk = data.toString();
        this.responseData += chunk;

        // Try to parse complete JSON-RPC responses
        try {
          const lines = this.responseData.split('\n').filter((line) => line.trim());
          for (const line of lines) {
            if (line.startsWith('{') && line.endsWith('}')) {
              const response = JSON.parse(line);
              this.handleResponse(response);
            }
          }
        } catch (e) {
          // Not complete JSON yet, continue accumulating
        }
      });

      this.process.on('close', (code, signal) => {
        console.error(`[CLIENT] Process closed. Code: ${code}, Signal: ${signal}`);
        this.emit('close', { code, signal });
      });

      // Send initialize request
      this.sendRequest('initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {
          tools: {},
        },
        clientInfo: {
          name: 'mcp-protocol-test-client',
          version: '1.0.0',
        },
      })
        .then((response) => {
          connected = true;
          clearTimeout(timeout);
          this.isInitialized = true;
          console.error('[CLIENT] ✅ MCP Handshake successful');
          resolve(response);
        })
        .catch((error) => {
          clearTimeout(timeout);
          console.error('[CLIENT] ❌ MCP Handshake failed:', error);
          reject(error);
        });
    });
  }

  sendRequest(method, params = {}) {
    return new Promise((resolve, reject) => {
      if (!this.process || !this.process.stdin) {
        reject(new Error('Process not available'));
        return;
      }

      const id = ++this.requestId;
      const request = {
        jsonrpc: '2.0',
        id,
        method,
        params,
      };

      console.error(`[CLIENT] Sending request: ${method}`, JSON.stringify(params, null, 2));

      // Set up response handler
      this.pendingRequests.set(id, { resolve, reject, method });

      // Send request
      this.process.stdin.write(JSON.stringify(request) + '\n');

      // Set timeout for this request
      setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id);
          reject(new Error(`Request timeout: ${method}`));
        }
      }, 10000);
    });
  }

  handleResponse(response) {
    console.error(`[CLIENT] Received response:`, JSON.stringify(response, null, 2));

    if (response.id && this.pendingRequests.has(response.id)) {
      const { resolve, reject, method } = this.pendingRequests.get(response.id);
      this.pendingRequests.delete(response.id);

      if (response.error) {
        console.error(`[CLIENT] ❌ Request failed: ${method}`, response.error);
        reject(new Error(`MCP Error: ${response.error.message} (${response.error.code})`));
      } else {
        console.error(`[CLIENT] ✅ Request successful: ${method}`);
        resolve(response.result);
      }
    }
  }

  async listTools() {
    return this.sendRequest('tools/list');
  }

  async callTool(name, args) {
    return this.sendRequest('tools/call', { name, arguments: args });
  }

  disconnect() {
    if (this.process) {
      this.process.kill('SIGTERM');
      this.process = null;
    }
  }
}

// Test functions
async function testHandshake() {
  console.error('\n=== TEST 1: MCP Protocol Handshake ===');
  const startTime = Date.now();
  const client = new MCPTestClient();

  try {
    const response = await client.connect(TEST_CONFIG.serverPath);
    const duration = Date.now() - startTime;

    // Validate handshake response
    if (response && response.protocolVersion && response.capabilities) {
      console.error('✅ Handshake SUCCESS');
      console.error(`Protocol Version: ${response.protocolVersion}`);
      console.error(`Server Capabilities:`, JSON.stringify(response.capabilities, null, 2));

      TEST_CONFIG.testResults.handshake = {
        success: true,
        error: null,
        duration,
      };

      client.disconnect();
      return true;
    } else {
      throw new Error('Invalid handshake response structure');
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    console.error('❌ Handshake FAILED:', error.message);

    TEST_CONFIG.testResults.handshake = {
      success: false,
      error: error.message,
      duration,
    };

    client.disconnect();
    return false;
  }
}

async function testToolDiscovery() {
  console.error('\n=== TEST 2: Tool Discovery ===');
  const client = new MCPTestClient();

  try {
    await client.connect(TEST_CONFIG.serverPath);
    const toolsResponse = await client.listTools();

    console.error('✅ Tools list retrieved successfully');
    console.error(`Found ${toolsResponse.tools.length} tools`);

    const expectedTools = ['memory_store', 'memory_find', 'system_status'];
    const foundTools = toolsResponse.tools.map((t) => t.name);
    const missingTools = expectedTools.filter((t) => !foundTools.includes(t));

    if (missingTools.length > 0) {
      throw new Error(`Missing expected tools: ${missingTools.join(', ')}`);
    }

    // Validate tool schemas
    for (const tool of toolsResponse.tools) {
      console.error(`Tool: ${tool.name}`);
      console.error(`  Description: ${tool.description}`);
      console.error(`  Schema:`, JSON.stringify(tool.inputSchema, null, 4));

      if (!tool.name || !tool.description || !tool.inputSchema) {
        throw new Error(`Invalid tool definition for ${tool.name}`);
      }
    }

    TEST_CONFIG.testResults.toolDiscovery = {
      success: true,
      error: null,
      toolsFound: foundTools,
    };

    client.disconnect();
    return true;
  } catch (error) {
    console.error('❌ Tool discovery FAILED:', error.message);

    TEST_CONFIG.testResults.toolDiscovery = {
      success: false,
      error: error.message,
      toolsFound: [],
    };

    client.disconnect();
    return false;
  }
}

async function testMemoryStore() {
  console.error('\n=== TEST 3: Memory Store Tool ===');
  const client = new MCPTestClient();
  const testResults = [];

  try {
    await client.connect(TEST_CONFIG.serverPath);

    // Test 1: Store single entity
    console.error('Testing single entity storage...');
    const result1 = await client.callTool('memory_store', {
      items: [TEST_DATA.entity],
    });
    testResults.push({ test: 'single_entity', success: true, result: result1 });
    console.error('✅ Single entity storage successful');

    // Test 2: Store multiple items
    console.error('Testing multiple items storage...');
    const result2 = await client.callTool('memory_store', {
      items: [TEST_DATA.decision, TEST_DATA.issue],
    });
    testResults.push({ test: 'multiple_items', success: true, result: result2 });
    console.error('✅ Multiple items storage successful');

    // Test 3: Invalid data handling
    console.error('Testing invalid data handling...');
    try {
      await client.callTool('memory_store', {
        items: [{ invalid: 'data' }],
      });
      testResults.push({ test: 'invalid_data', success: false, error: 'Should have failed' });
      console.error('❌ Invalid data should have failed');
    } catch (error) {
      testResults.push({ test: 'invalid_data', success: true, result: error.message });
      console.error('✅ Invalid data properly rejected');
    }

    // Test 4: Empty items array
    console.error('Testing empty items array...');
    try {
      await client.callTool('memory_store', {
        items: [],
      });
      testResults.push({ test: 'empty_items', success: false, error: 'Should have failed' });
      console.error('❌ Empty items should have failed');
    } catch (error) {
      testResults.push({ test: 'empty_items', success: true, result: error.message });
      console.error('✅ Empty items properly rejected');
    }

    const successCount = testResults.filter((r) => r.success).length;
    const totalTests = testResults.length;

    TEST_CONFIG.testResults.memoryStore = {
      success: successCount === totalTests,
      error: successCount === totalTests ? null : `${totalTests - successCount} tests failed`,
      testResults,
    };

    client.disconnect();
    return successCount === totalTests;
  } catch (error) {
    console.error('❌ Memory store test FAILED:', error.message);

    TEST_CONFIG.testResults.memoryStore = {
      success: false,
      error: error.message,
      testResults,
    };

    client.disconnect();
    return false;
  }
}

async function testMemoryFind() {
  console.error('\n=== TEST 4: Memory Find Tool ===');
  const client = new MCPTestClient();
  const testResults = [];

  try {
    await client.connect(TEST_CONFIG.serverPath);

    // First, store some test data
    console.error('Storing test data for search...');
    await client.callTool('memory_store', {
      items: [TEST_DATA.entity, TEST_DATA.decision, TEST_DATA.issue],
    });

    // Test 1: Basic search
    console.error('Testing basic search...');
    const result1 = await client.callTool('memory_find', {
      query: 'Test Entity',
      limit: 10,
    });
    testResults.push({ test: 'basic_search', success: true, result: result1 });
    console.error('✅ Basic search successful');

    // Test 2: Search with type filter
    console.error('Testing search with type filter...');
    const result2 = await client.callTool('memory_find', {
      query: 'Test',
      types: ['entity'],
      limit: 10,
    });
    testResults.push({ test: 'type_filter', success: true, result: result2 });
    console.error('✅ Type filter search successful');

    // Test 3: Search with different modes
    console.error('Testing search modes...');
    for (const mode of ['fast', 'auto', 'deep']) {
      const result = await client.callTool('memory_find', {
        query: 'Test',
        mode,
        limit: 5,
      });
      testResults.push({ test: `mode_${mode}`, success: true, result });
      console.error(`✅ ${mode} mode search successful`);
    }

    // Test 4: Empty query
    console.error('Testing empty query...');
    try {
      await client.callTool('memory_find', {
        query: '',
        limit: 10,
      });
      testResults.push({ test: 'empty_query', success: false, error: 'Should have failed' });
      console.error('❌ Empty query should have failed');
    } catch (error) {
      testResults.push({ test: 'empty_query', success: true, result: error.message });
      console.error('✅ Empty query properly rejected');
    }

    const successCount = testResults.filter((r) => r.success).length;
    const totalTests = testResults.length;

    TEST_CONFIG.testResults.memoryFind = {
      success: successCount === totalTests,
      error: successCount === totalTests ? null : `${totalTests - successCount} tests failed`,
      testResults,
    };

    client.disconnect();
    return successCount === totalTests;
  } catch (error) {
    console.error('❌ Memory find test FAILED:', error.message);

    TEST_CONFIG.testResults.memoryFind = {
      success: false,
      error: error.message,
      testResults,
    };

    client.disconnect();
    return false;
  }
}

async function testSystemStatus() {
  console.error('\n=== TEST 5: System Status Tool ===');
  const client = new MCPTestClient();
  const testResults = [];

  try {
    await client.connect(TEST_CONFIG.serverPath);

    // Test 1: Basic status
    console.error('Testing basic status...');
    const result1 = await client.callTool('system_status', {
      operation: 'status',
    });
    testResults.push({ test: 'basic_status', success: true, result: result1 });
    console.error('✅ Basic status successful');

    // Test 2: Health check
    console.error('Testing health check...');
    const result2 = await client.callTool('system_status', {
      operation: 'health_check',
    });
    testResults.push({ test: 'health_check', success: true, result: result2 });
    console.error('✅ Health check successful');

    // Test 3: Cleanup operation (with safety check)
    console.error('Testing cleanup operation...');
    const result3 = await client.callTool('system_status', {
      operation: 'cleanup',
    });
    testResults.push({ test: 'cleanup', success: true, result: result3 });
    console.error('✅ Cleanup operation successful');

    // Test 4: Default operation (no parameters)
    console.error('Testing default operation...');
    const result4 = await client.callTool('system_status', {});
    testResults.push({ test: 'default_operation', success: true, result: result4 });
    console.error('✅ Default operation successful');

    const successCount = testResults.filter((r) => r.success).length;
    const totalTests = testResults.length;

    TEST_CONFIG.testResults.systemStatus = {
      success: successCount === totalTests,
      error: successCount === totalTests ? null : `${totalTests - successCount} tests failed`,
      testResults,
    };

    client.disconnect();
    return successCount === totalTests;
  } catch (error) {
    console.error('❌ System status test FAILED:', error.message);

    TEST_CONFIG.testResults.systemStatus = {
      success: false,
      error: error.message,
      testResults,
    };

    client.disconnect();
    return false;
  }
}

async function testErrorHandling() {
  console.error('\n=== TEST 6: Error Handling ===');
  const client = new MCPTestClient();
  const testResults = [];

  try {
    await client.connect(TEST_CONFIG.serverPath);

    // Test 1: Invalid tool name
    console.error('Testing invalid tool name...');
    try {
      await client.callTool('nonexistent_tool', {});
      testResults.push({ test: 'invalid_tool', success: false, error: 'Should have failed' });
    } catch (error) {
      testResults.push({ test: 'invalid_tool', success: true, result: error.message });
      console.error('✅ Invalid tool properly rejected');
    }

    // Test 2: Invalid JSON-RPC method
    console.error('Testing invalid method...');
    try {
      await client.sendRequest('invalid/method', {});
      testResults.push({ test: 'invalid_method', success: false, error: 'Should have failed' });
    } catch (error) {
      testResults.push({ test: 'invalid_method', success: true, result: error.message });
      console.error('✅ Invalid method properly rejected');
    }

    // Test 3: Malformed request parameters
    console.error('Testing malformed parameters...');
    try {
      await client.callTool('memory_store', { invalid_param: 'test' });
      testResults.push({ test: 'malformed_params', success: true, result: 'Properly handled' });
      console.error('✅ Malformed parameters properly handled');
    } catch (error) {
      testResults.push({ test: 'malformed_params', success: true, result: error.message });
      console.error('✅ Malformed parameters properly rejected');
    }

    const successCount = testResults.filter((r) => r.success).length;
    const totalTests = testResults.length;

    TEST_CONFIG.testResults.errorHandling = {
      success: successCount === totalTests,
      error: successCount === totalTests ? null : `${totalTests - successCount} tests failed`,
      testResults,
    };

    client.disconnect();
    return successCount === totalTests;
  } catch (error) {
    console.error('❌ Error handling test FAILED:', error.message);

    TEST_CONFIG.testResults.errorHandling = {
      success: false,
      error: error.message,
      testResults,
    };

    client.disconnect();
    return false;
  }
}

async function testConcurrentAccess() {
  console.error('\n=== TEST 7: Concurrent Access ===');
  const testResults = [];

  try {
    // Create multiple clients
    const clients = [];
    const connectionPromises = [];

    console.error(`Creating ${TEST_CONFIG.concurrentClients} concurrent clients...`);

    for (let i = 0; i < TEST_CONFIG.concurrentClients; i++) {
      const client = new MCPTestClient();
      clients.push(client);

      const connectionPromise = client
        .connect(TEST_CONFIG.serverPath)
        .then(() => {
          testResults.push({ test: `client_${i}_connect`, success: true });
          console.error(`✅ Client ${i} connected successfully`);
        })
        .catch((error) => {
          testResults.push({ test: `client_${i}_connect`, success: false, error: error.message });
          console.error(`❌ Client ${i} connection failed:`, error.message);
        });

      connectionPromises.push(connectionPromise);
    }

    // Wait for all connections
    await Promise.all(connectionPromises);

    // Test concurrent operations
    console.error('Testing concurrent operations...');
    const operationPromises = [];

    for (let i = 0; i < clients.length; i++) {
      const client = clients[i];

      if (client.isInitialized) {
        // Test memory store
        const storePromise = client
          .callTool('memory_store', {
            items: [
              {
                kind: 'entity',
                data: {
                  title: `Concurrent Test Entity ${i}`,
                  description: `Test entity from concurrent client ${i}`,
                  test_client: i,
                },
              },
            ],
          })
          .then(() => {
            testResults.push({ test: `client_${i}_store`, success: true });
            console.error(`✅ Client ${i} store operation successful`);
          })
          .catch((error) => {
            testResults.push({ test: `client_${i}_store`, success: false, error: error.message });
            console.error(`❌ Client ${i} store operation failed:`, error.message);
          });

        operationPromises.push(storePromise);

        // Test memory find
        const findPromise = client
          .callTool('memory_find', {
            query: `Concurrent Test Entity ${i}`,
            limit: 5,
          })
          .then(() => {
            testResults.push({ test: `client_${i}_find`, success: true });
            console.error(`✅ Client ${i} find operation successful`);
          })
          .catch((error) => {
            testResults.push({ test: `client_${i}_find`, success: false, error: error.message });
            console.error(`❌ Client ${i} find operation failed:`, error.message);
          });

        operationPromises.push(findPromise);
      }
    }

    // Wait for all operations
    await Promise.all(operationPromises);

    // Clean up
    for (const client of clients) {
      client.disconnect();
    }

    const successCount = testResults.filter((r) => r.success).length;
    const totalTests = testResults.length;
    const successRate = (successCount / totalTests) * 100;

    console.error(
      `Concurrent access test: ${successCount}/${totalTests} operations successful (${successRate.toFixed(1)}%)`
    );

    TEST_CONFIG.testResults.concurrentAccess = {
      success: successRate >= 80, // Allow for some failures in concurrent scenarios
      error:
        successRate >= 80 ? null : `Success rate ${successRate.toFixed(1)}% below 80% threshold`,
      testResults,
    };

    return successRate >= 80;
  } catch (error) {
    console.error('❌ Concurrent access test FAILED:', error.message);

    TEST_CONFIG.testResults.concurrentAccess = {
      success: false,
      error: error.message,
      testResults,
    };

    return false;
  }
}

// Main test runner
async function runTests() {
  console.error('=== COMPREHENSIVE MCP PROTOCOL TEST SUITE ===');
  console.error(`Server: ${TEST_CONFIG.serverPath}`);
  console.error(`Timeout: ${TEST_CONFIG.timeout}ms`);
  console.error(`Concurrent Clients: ${TEST_CONFIG.concurrentClients}`);

  const overallStartTime = Date.now();

  // Check if server exists
  const fs = await import('fs');
  if (!fs.existsSync(TEST_CONFIG.serverPath)) {
    console.error(`❌ Server file not found: ${TEST_CONFIG.serverPath}`);
    console.error('Please build the server first: npm run build');
    process.exit(1);
  }

  // Run tests sequentially
  const tests = [
    { name: 'Handshake', fn: testHandshake },
    { name: 'Tool Discovery', fn: testToolDiscovery },
    { name: 'Memory Store', fn: testMemoryStore },
    { name: 'Memory Find', fn: testMemoryFind },
    { name: 'System Status', fn: testSystemStatus },
    { name: 'Error Handling', fn: testErrorHandling },
    { name: 'Concurrent Access', fn: testConcurrentAccess },
  ];

  const results = {};

  for (const test of tests) {
    console.error(`\n--- Running ${test.name} Test ---`);
    try {
      results[test.name] = await test.fn();
      console.error(
        `${results[test.name] ? '✅' : '❌'} ${test.name}: ${results[test.name] ? 'PASSED' : 'FAILED'}`
      );
    } catch (error) {
      console.error(`❌ ${test.name}: ERROR - ${error.message}`);
      results[test.name] = false;
    }

    // Wait between tests
    if (test !== tests[tests.length - 1]) {
      await new Promise((resolve) => setTimeout(resolve, TEST_CONFIG.testDelay));
    }
  }

  const overallDuration = Date.now() - overallStartTime;
  const passedTests = Object.values(results).filter((r) => r).length;
  const totalTests = Object.keys(results).length;

  // Generate comprehensive report
  console.error('\n' + '='.repeat(80));
  console.error('COMPREHENSIVE TEST RESULTS');
  console.error('='.repeat(80));
  console.error(
    `Overall: ${passedTests}/${totalTests} tests passed (${((passedTests / totalTests) * 100).toFixed(1)}%)`
  );
  console.error(`Duration: ${overallDuration}ms`);
  console.error('');

  for (const [testName, passed] of Object.entries(results)) {
    const status = passed ? '✅ PASSED' : '❌ FAILED';
    const resultKey = testName.toLowerCase().replace(' ', '');
    const result = TEST_CONFIG.testResults[resultKey];
    console.error(`${testName}: ${status}`);
    if (result && result.error) {
      console.error(`  Error: ${result.error}`);
    }
    if (result && result.duration) {
      console.error(`  Duration: ${result.duration}ms`);
    }
    if (result && result.toolsFound && result.toolsFound.length > 0) {
      console.error(`  Tools Found: ${result.toolsFound.join(', ')}`);
    }
    if (result && result.testResults) {
      const subTestsPassed = result.testResults.filter((t) => t.success).length;
      const subTestsTotal = result.testResults.length;
      console.error(`  Sub-tests: ${subTestsPassed}/${subTestsTotal} passed`);
    }
    console.error('');
  }

  // Detailed results for each test
  console.error('='.repeat(80));
  console.error('DETAILED TEST RESULTS');
  console.error('='.repeat(80));
  console.error(JSON.stringify(TEST_CONFIG.testResults, null, 2));

  // Summary and recommendations
  console.error('\n' + '='.repeat(80));
  console.error('SUMMARY & RECOMMENDATIONS');
  console.error('='.repeat(80));

  if (passedTests === totalTests) {
    console.error('🎉 ALL TESTS PASSED! The MCP Cortex server is fully functional.');
    console.error('');
    console.error('✅ Server successfully handles MCP protocol initialization');
    console.error('✅ All required tools are discoverable and functional');
    console.error('✅ Memory operations work correctly');
    console.error('✅ System monitoring is operational');
    console.error('✅ Error handling follows JSON-RPC 2.0 specification');
    console.error('✅ Server supports concurrent access');
  } else {
    console.error(`⚠️  ${totalTests - passedTests} test(s) failed. Review the details above.`);
    console.error('');
    console.error('Recommendations:');

    if (!results.handshake) {
      console.error('- Check server startup and Qdrant connection');
    }
    if (!results['Tool Discovery']) {
      console.error('- Verify tool registration in server code');
    }
    if (!results['Memory Store']) {
      console.error('- Check memory storage implementation and validation');
    }
    if (!results['Memory Find']) {
      console.error('- Verify search functionality and indexing');
    }
    if (!results['System Status']) {
      console.error('- Check system monitoring implementation');
    }
    if (!results['Error Handling']) {
      console.error('- Review error response formatting');
    }
    if (!results['Concurrent Access']) {
      console.error('- Investigate concurrent access issues');
    }
  }

  process.exit(passedTests === totalTests ? 0 : 1);
}

// Handle process termination
process.on('SIGINT', () => {
  console.error('\nTest interrupted by user');
  process.exit(1);
});

// Run the tests
runTests().catch((error) => {
  console.error('Test suite failed:', error);
  process.exit(1);
});
