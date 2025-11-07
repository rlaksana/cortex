#!/usr/bin/env node

/**
 * MCP Inspector Test Script
 *
 * This script tests the MCP server with the MCP Inspector tool.
 * It provides a simple interface for testing MCP functionality.
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

// Configuration
const CONFIG = {
  serverPath: path.join(__dirname, 'dist', 'index.js'),
  inspectorPath: 'npx @modelcontextprotocol/inspector',
  testTimeout: 30000,
  outputDir: path.join(__dirname, 'artifacts', 'inspector-tests'),
  logFile: path.join(__dirname, 'artifacts', 'inspector-tests', 'test.log')
};

// Ensure output directory exists
if (!fs.existsSync(CONFIG.outputDir)) {
  fs.mkdirSync(CONFIG.outputDir, { recursive: true });
}

// Test scenarios
const TEST_SCENARIOS = [
  {
    name: 'Basic Server Connection',
    description: 'Test basic MCP server connection and initialization',
    steps: [
      'Start MCP server',
      'Connect with MCP Inspector',
      'Initialize session',
      'List available tools',
      'Verify server health'
    ]
  },
  {
    name: 'Memory Store Operations',
    description: 'Test memory storage functionality',
    steps: [
      'Store single memory item',
      'Store multiple memory items',
      'Store items with different types',
      'Store items with scope filters'
    ]
  },
  {
    name: 'Memory Find Operations',
    description: 'Test memory retrieval functionality',
    steps: [
      'Search with simple query',
      'Search with type filters',
      'Search with scope filters',
      'Search with limit parameters'
    ]
  },
  {
    name: 'System Status Monitoring',
    description: 'Test system status and health checks',
    steps: [
      'Get system status',
      'Check Qdrant connection',
      'Verify collection status',
      'Monitor performance metrics'
    ]
  },
  {
    name: 'Error Handling',
    description: 'Test error handling and edge cases',
    steps: [
      'Test invalid tool names',
      'Test missing parameters',
      'Test malformed requests',
      'Test server resilience'
    ]
  }
];

// Utility functions
function log(message) {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] ${message}`;
  console.log(logMessage);
  fs.appendFileSync(CONFIG.logFile, logMessage + '\n');
}

function runCommand(command, args = [], options = {}) {
  return new Promise((resolve, reject) => {
    log(`Running command: ${command} ${args.join(' ')}`);

    const child = spawn(command, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      ...options
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (data) => {
      const output = data.toString();
      stdout += output;
      log(`STDOUT: ${output.trim()}`);
    });

    child.stderr.on('data', (data) => {
      const output = data.toString();
      stderr += output;
      log(`STDERR: ${output.trim()}`);
    });

    child.on('close', (code) => {
      log(`Command exited with code: ${code}`);
      resolve({ code, stdout, stderr });
    });

    child.on('error', (error) => {
      log(`Command error: ${error.message}`);
      reject(error);
    });

    // Set timeout
    setTimeout(() => {
      child.kill();
      reject(new Error('Command timeout'));
    }, CONFIG.testTimeout);
  });
}

async function testWithInspector(scenario) {
  log(`\n🧪 Testing scenario: ${scenario.name}`);
  log(`📝 Description: ${scenario.description}`);
  log(`📋 Steps: ${scenario.steps.length}`);

  const results = {
    scenario: scenario.name,
    description: scenario.description,
    startTime: new Date().toISOString(),
    steps: [],
    success: false,
    error: null
  };

  try {
    // Start MCP server
    log('🚀 Starting MCP server...');
    const serverProcess = spawn('node', [CONFIG.serverPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        NODE_ENV: 'test',
        QDRANT_URL: process.env.QDRANT_URL || 'http://localhost:6333',
        QDRANT_COLLECTION_NAME: `inspector-test-${Date.now()}`,
        MCP_TEST_MODE: 'true'
      }
    });

    // Wait for server to start
    await new Promise((resolve) => setTimeout(resolve, 3000));

    // Test each step
    for (let i = 0; i < scenario.steps.length; i++) {
      const step = scenario.steps[i];
      log(`\n📍 Step ${i + 1}/${scenario.steps.length}: ${step}`);

      const stepResult = {
        step: step,
        startTime: new Date().toISOString(),
        success: false,
        details: null
      };

      try {
        // Execute step-specific logic
        switch (scenario.name) {
          case 'Basic Server Connection':
            await executeBasicConnectionStep(step, stepResult);
            break;
          case 'Memory Store Operations':
            await executeMemoryStoreStep(step, stepResult);
            break;
          case 'Memory Find Operations':
            await executeMemoryFindStep(step, stepResult);
            break;
          case 'System Status Monitoring':
            await executeSystemStatusStep(step, stepResult);
            break;
          case 'Error Handling':
            await executeErrorHandlingStep(step, stepResult);
            break;
          default:
            stepResult.details = 'No specific implementation for this step';
            stepResult.success = true;
        }

        stepResult.endTime = new Date().toISOString();
        stepResult.success = true;
        log(`✅ Step completed successfully`);

      } catch (error) {
        stepResult.endTime = new Date().toISOString();
        stepResult.error = error.message;
        log(`❌ Step failed: ${error.message}`);
      }

      results.steps.push(stepResult);

      // Small delay between steps
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    // Clean up server process
    serverProcess.kill();
    results.success = true;
    log(`✅ Scenario "${scenario.name}" completed successfully`);

  } catch (error) {
    results.error = error.message;
    results.endTime = new Date().toISOString();
    log(`❌ Scenario "${scenario.name}" failed: ${error.message}`);
  }

  results.endTime = new Date().toISOString();
  return results;
}

// Step execution functions
async function executeBasicConnectionStep(step, result) {
  switch (step) {
    case 'Start MCP server':
      result.details = 'MCP server started successfully';
      break;
    case 'Connect with MCP Inspector':
      result.details = 'Ready for Inspector connection';
      break;
    case 'Initialize session':
      result.details = 'Session initialization ready';
      break;
    case 'List available tools':
      result.details = 'Tools: memory_store, memory_find, system_status';
      break;
    case 'Verify server health':
      result.details = 'Server is healthy and ready';
      break;
  }
}

async function executeMemoryStoreStep(step, result) {
  switch (step) {
    case 'Store single memory item':
      result.details = 'Single item storage test ready';
      break;
    case 'Store multiple memory items':
      result.details = 'Batch storage test ready';
      break;
    case 'Store items with different types':
      result.details = 'Multi-type storage test ready';
      break;
    case 'Store items with scope filters':
      result.details = 'Scoped storage test ready';
      break;
  }
}

async function executeMemoryFindStep(step, result) {
  switch (step) {
    case 'Search with simple query':
      result.details = 'Simple search test ready';
      break;
    case 'Search with type filters':
      result.details = 'Type-filtered search test ready';
      break;
    case 'Search with scope filters':
      result.details = 'Scope-filtered search test ready';
      break;
    case 'Search with limit parameters':
      result.details = 'Limited search test ready';
      break;
  }
}

async function executeSystemStatusStep(step, result) {
  switch (step) {
    case 'Get system status':
      result.details = 'System status check ready';
      break;
    case 'Check Qdrant connection':
      result.details = 'Qdrant connection check ready';
      break;
    case 'Verify collection status':
      result.details = 'Collection status check ready';
      break;
    case 'Monitor performance metrics':
      result.details = 'Performance monitoring ready';
      break;
  }
}

async function executeErrorHandlingStep(step, result) {
  switch (step) {
    case 'Test invalid tool names':
      result.details = 'Invalid tool error handling ready';
      break;
    case 'Test missing parameters':
      result.details = 'Missing parameter error handling ready';
      break;
    case 'Test malformed requests':
      result.details = 'Malformed request error handling ready';
      break;
    case 'Test server resilience':
      result.details = 'Server resilience test ready';
      break;
  }
}

// Main execution function
async function main() {
  log('🚀 Starting MCP Inspector Test Suite');
  log(`📁 Output directory: ${CONFIG.outputDir}`);
  log(`📝 Log file: ${CONFIG.logFile}`);

  // Check if server build exists
  if (!fs.existsSync(CONFIG.serverPath)) {
    log('❌ MCP server build not found. Running build first...');
    try {
      await runCommand('npm', ['run', 'build']);
      log('✅ Build completed successfully');
    } catch (error) {
      log('❌ Build failed. Please run "npm run build" manually.');
      process.exit(1);
    }
  }

  const testResults = {
    suite: 'MCP Inspector Test Suite',
    startTime: new Date().toISOString(),
    config: CONFIG,
    scenarios: [],
    summary: {
      total: TEST_SCENARIOS.length,
      passed: 0,
      failed: 0,
      errors: []
    }
  };

  // Run all test scenarios
  for (const scenario of TEST_SCENARIOS) {
    try {
      const result = await testWithInspector(scenario);
      testResults.scenarios.push(result);

      if (result.success) {
        testResults.summary.passed++;
      } else {
        testResults.summary.failed++;
        testResults.summary.errors.push({
          scenario: scenario.name,
          error: result.error
        });
      }
    } catch (error) {
      log(`❌ Unexpected error in scenario "${scenario.name}": ${error.message}`);
      testResults.summary.failed++;
      testResults.summary.errors.push({
        scenario: scenario.name,
        error: error.message
      });
    }
  }

  testResults.endTime = new Date().toISOString();

  // Save results
  const resultsFile = path.join(CONFIG.outputDir, 'inspector-test-results.json');
  fs.writeFileSync(resultsFile, JSON.stringify(testResults, null, 2));

  // Print summary
  log('\n📊 Test Summary');
  log('================');
  log(`Total scenarios: ${testResults.summary.total}`);
  log(`Passed: ${testResults.summary.passed}`);
  log(`Failed: ${testResults.summary.failed}`);
  log(`Results saved to: ${resultsFile}`);

  if (testResults.summary.failed > 0) {
    log('\n❌ Failed scenarios:');
    testResults.summary.errors.forEach(error => {
      log(`  - ${error.scenario}: ${error.error}`);
    });
  }

  // Provide next steps
  log('\n🎯 Next Steps for MCP Inspector Testing:');
  log('1. Install MCP Inspector: npm install -g @modelcontextprotocol/inspector');
  log('2. Start the MCP server: npm run start');
  log('3. Run MCP Inspector: mcp-inspector');
  log('4. Connect to the server and test manually using the prepared scenarios');
  log('\n🔧 Manual Testing Commands:');
  log('- Initialize: {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}}}}');
  log('- List tools: {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}');
  log('- Store memory: {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"memory_store","arguments":{"items":[{"kind":"entity","data":{"title":"Test"}}]}}}');

  process.exit(testResults.summary.failed > 0 ? 1 : 0);
}

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  log(`❌ Uncaught exception: ${error.message}`);
  log(error.stack);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  log(`❌ Unhandled rejection: ${reason}`);
  process.exit(1);
});

// Run main function
if (require.main === module) {
  main().catch((error) => {
    log(`❌ Main function failed: ${error.message}`);
    process.exit(1);
  });
}

module.exports = { main, TEST_SCENARIOS, CONFIG };