#!/usr/bin/env node

/**
 * MCP Inspector Test Runner Script
 *
 * Convenience script to run MCP Inspector tests with proper setup and cleanup.
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

// Configuration
const CONFIG = {
  testScript: path.join(__dirname, '..', 'test-mcp-inspector.js'),
  serverPath: path.join(__dirname, '..', 'dist', 'index.js'),
  outputDir: path.join(__dirname, '..', 'artifacts', 'inspector-tests'),
  inspectorPort: 3001,
  qdrantPort: 6333
};

// Utility functions
function log(message) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${message}`);
}

async function runCommand(command, args = [], options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: 'inherit',
      ...options
    });

    child.on('close', (code) => {
      resolve(code);
    });

    child.on('error', (error) => {
      reject(error);
    });
  });
}

async function checkPrerequisites() {
  log('🔍 Checking prerequisites...');

  // Check if Node.js is available
  try {
    await runCommand('node', ['--version']);
    log('✅ Node.js is available');
  } catch (error) {
    log('❌ Node.js is not available');
    return false;
  }

  // Check if npm is available
  try {
    await runCommand('npm', ['--version']);
    log('✅ npm is available');
  } catch (error) {
    log('❌ npm is not available');
    return false;
  }

  // Check if project dependencies are installed
  const packageJsonPath = path.join(__dirname, '..', 'package.json');
  const nodeModulesPath = path.join(__dirname, '..', 'node_modules');

  if (!fs.existsSync(packageJsonPath)) {
    log('❌ package.json not found');
    return false;
  }

  if (!fs.existsSync(nodeModulesPath)) {
    log('⚠️ node_modules not found, running npm install...');
    try {
      await runCommand('npm', ['install'], { cwd: path.join(__dirname, '..') });
      log('✅ Dependencies installed');
    } catch (error) {
      log('❌ Failed to install dependencies');
      return false;
    }
  } else {
    log('✅ Dependencies are installed');
  }

  return true;
}

async function setupTestEnvironment() {
  log('🛠️ Setting up test environment...');

  // Create output directory
  if (!fs.existsSync(CONFIG.outputDir)) {
    fs.mkdirSync(CONFIG.outputDir, { recursive: true });
    log(`📁 Created output directory: ${CONFIG.outputDir}`);
  }

  // Set environment variables
  process.env.NODE_ENV = 'test';
  process.env.QDRANT_URL = process.env.QDRANT_URL || `http://localhost:${CONFIG.qdrantPort}`;
  process.env.QDRANT_COLLECTION_NAME = `inspector-test-${Date.now()}`;
  process.env.MCP_TEST_MODE = 'true';

  log('✅ Test environment setup completed');
  return true;
}

async function runTests() {
  log('🧪 Running MCP Inspector tests...');

  try {
    // Run the test script
    const exitCode = await runCommand('node', [CONFIG.testScript], {
      cwd: path.join(__dirname, '..')
    });

    if (exitCode === 0) {
      log('✅ All tests passed successfully');
      return true;
    } else {
      log(`❌ Tests failed with exit code: ${exitCode}`);
      return false;
    }
  } catch (error) {
    log(`❌ Failed to run tests: ${error.message}`);
    return false;
  }
}

async function generateReport() {
  log('📊 Generating test report...');

  const resultsFile = path.join(CONFIG.outputDir, 'inspector-test-results.json');

  if (fs.existsSync(resultsFile)) {
    try {
      const results = JSON.parse(fs.readFileSync(resultsFile, 'utf8'));

      // Generate summary report
      const reportFile = path.join(CONFIG.outputDir, 'test-summary.md');
      const report = generateMarkdownReport(results);

      fs.writeFileSync(reportFile, report);
      log(`📄 Test report generated: ${reportFile}`);

      return true;
    } catch (error) {
      log(`❌ Failed to generate report: ${error.message}`);
      return false;
    }
  } else {
    log('⚠️ No test results found to generate report');
    return false;
  }
}

function generateMarkdownReport(results) {
  const summary = results.summary;
  const timestamp = new Date().toISOString();

  return `# MCP Inspector Test Report

**Generated:** ${timestamp}
**Test Suite:** ${results.suite}

## Summary

- **Total Scenarios:** ${summary.total}
- **Passed:** ${summary.passed} ✅
- **Failed:** ${summary.failed} ❌
- **Success Rate:** ${((summary.passed / summary.total) * 100).toFixed(1)}%

## Test Results

${results.scenarios.map(scenario => `
### ${scenario.scenario}

**Status:** ${scenario.success ? '✅ PASSED' : '❌ FAILED'}
**Description:** ${scenario.description}
**Duration:** ${new Date(scenario.endTime) - new Date(scenario.startTime)}ms

**Steps:**
${scenario.steps.map(step => `
- ${step.step}: ${step.success ? '✅' : '❌'} ${step.details || step.error || ''}
`).join('')}

${scenario.error ? `**Error:** ${scenario.error}` : ''}
`).join('')}

${summary.errors.length > 0 ? `
## Failed Tests

${summary.errors.map(error => `
- **${error.scenario}:** ${error.error}
`).join('')}
` : ''}

## Configuration

- **Server Path:** ${results.config.serverPath}
- **Output Directory:** ${results.config.outputDir}
- **Test Timeout:** ${results.config.testTimeout}ms

## Next Steps

1. Review failed tests and fix any issues
2. Run manual tests with MCP Inspector if needed
3. Update test scenarios based on findings

---

*This report was generated automatically by the MCP Inspector test runner.*
`;
}

async function showManualInstructions() {
  log('\n🎯 Manual Testing Instructions');
  log('=============================');
  log('');
  log('If you want to test manually with MCP Inspector, follow these steps:');
  log('');
  log('1. Install MCP Inspector:');
  log('   npm install -g @modelcontextprotocol/inspector');
  log('');
  log('2. Start the MCP server in a separate terminal:');
  log('   npm run start');
  log('');
  log('3. Start MCP Inspector:');
  log('   mcp-inspector');
  log('');
  log('4. In MCP Inspector, connect to localhost:6333 (or your configured port)');
  log('');
  log('5. Test the following scenarios:');
  log('');
  log('   a) Basic Connection:');
  log('      - Initialize the session');
  log('      - List available tools');
  log('      - Check server status');
  log('');
  log('   b) Memory Storage:');
  log('      - Store a single entity');
  log('      - Store multiple items of different types');
  log('      - Verify storage success');
  log('');
  log('   c) Memory Retrieval:');
  log('      - Search with simple queries');
  log('      - Filter by type and scope');
  log('      - Test limit and pagination');
  log('');
  log('   d) System Status:');
  log('      - Get system status');
  log('      - Check database connection');
  log('      - Verify collection health');
  log('');
  log('6. Sample MCP Inspector commands:');
  log('');
  log('   Initialize:');
  log('   ```json');
  log('   {');
  log('     "jsonrpc": "2.0",');
  log('     "id": 1,');
  log('     "method": "initialize",');
  log('     "params": {');
  log('       "protocolVersion": "2025-06-18",');
  log('       "capabilities": { "tools": {} }');
  log('     }');
  log('   }');
  log('   ```');
  log('');
  log('   List Tools:');
  log('   ```json');
  log('   {');
  log('     "jsonrpc": "2.0",');
  log('     "id": 2,');
  log('     "method": "tools/list",');
  log('     "params": {}');
  log('   }');
  log('   ```');
  log('');
  log('   Store Memory:');
  log('   ```json');
  log('   {');
  log('     "jsonrpc": "2.0",');
  log('     "id": 3,');
  log('     "method": "tools/call",');
  log('     "params": {');
  log('       "name": "memory_store",');
  log('       "arguments": {');
  log('         "items": [{');
  log('           "kind": "entity",');
  log('           "data": {');
  log('             "title": "Test Entity",');
  log('             "description": "A test entity for manual verification"');
  log('           }');
  log('         }]');
  log('       }');
  log('     }');
  log('   }');
  log('   ```');
  log('');
  log('   Find Memory:');
  log('   ```json');
  log('   {');
  log('     "jsonrpc": "2.0",');
  log('     "id": 4,');
  log('     "method": "tools/call",');
  log('     "params": {');
  log('       "name": "memory_find",');
  log('       "arguments": {');
  log('         "query": "test",');
  log('         "limit": 10');
  log('       }');
  log('     }');
  log('   }');
  log('   ```');
  log('');
}

// Main execution function
async function main() {
  log('🚀 MCP Inspector Test Runner');
  log('============================');

  const startTime = Date.now();

  try {
    // Check prerequisites
    const prerequisitesOk = await checkPrerequisites();
    if (!prerequisitesOk) {
      log('❌ Prerequisites check failed');
      process.exit(1);
    }

    // Setup test environment
    const setupOk = await setupTestEnvironment();
    if (!setupOk) {
      log('❌ Test environment setup failed');
      process.exit(1);
    }

    // Run tests
    const testsPassed = await runTests();

    // Generate report
    await generateReport();

    // Show manual instructions
    await showManualInstructions();

    const duration = Date.now() - startTime;
    log(`\n⏱️ Total duration: ${duration}ms`);

    if (testsPassed) {
      log('🎉 All tests completed successfully!');
      process.exit(0);
    } else {
      log('❌ Some tests failed. Check the report for details.');
      process.exit(1);
    }

  } catch (error) {
    log(`❌ Test runner failed: ${error.message}`);
    log(error.stack);
    process.exit(1);
  }
}

// Handle command line arguments
const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
  console.log(`
MCP Inspector Test Runner

Usage: node run-mcp-inspector-tests.js [options]

Options:
  --help, -h     Show this help message
  --setup-only   Only run setup without tests
  --no-report    Skip report generation
  --manual       Show manual testing instructions only

Environment Variables:
  QDRANT_URL     URL for Qdrant database (default: http://localhost:6333)
  NODE_ENV       Node environment (default: test)
`);
  process.exit(0);
}

if (args.includes('--manual')) {
  showManualInstructions();
  process.exit(0);
}

if (args.includes('--setup-only')) {
  checkPrerequisites().then(ok => {
    if (ok) {
      setupTestEnvironment().then(() => {
        log('✅ Setup completed successfully');
        process.exit(0);
      });
    } else {
      log('❌ Setup failed');
      process.exit(1);
    }
  });
  return;
}

// Run main function
if (require.main === module) {
  main().catch((error) => {
    log(`❌ Main function failed: ${error.message}`);
    process.exit(1);
  });
}

module.exports = { main, CONFIG };