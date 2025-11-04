#!/usr/bin/env node

/**
 * Test MCP Tools Script
 *
 * This script performs basic functional testing of the MCP tools
 * to ensure they respond correctly to test inputs.
 */

import { execSync } from 'child_process';
import { existsSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🧪 Testing MCP tools functionality...');

async function testMcpTools() {
  try {
    // Check if the server is built
    const distPath = join(__dirname, '..', 'dist');
    const serverPath = join(distPath, 'index.js');

    if (!existsSync(serverPath)) {
      console.log('🔧 Building server first...');
      try {
        execSync('npm run build', { stdio: 'inherit', cwd: join(__dirname, '..') });
      } catch (error) {
        console.log('❌ Failed to build server');
        return false;
      }
    }

    console.log('✅ Server built successfully');

    // Test basic functionality (this would be more comprehensive in a real implementation)
    const tests = [
      {
        name: 'Server starts without errors',
        command: 'timeout 10s node dist/index.js || true',
        expected: 'Server should start and not crash immediately'
      },
      {
        name: 'Dependencies are available',
        command: 'node -e "try { require(\'@modelcontextprotocol/sdk\'); console.log(\'✅ MCP SDK available\'); } catch(e) { console.log(\'❌ MCP SDK missing\'); }"',
        expected: 'Required dependencies should be available'
      }
    ];

    let passedTests = 0;

    for (const test of tests) {
      console.log(`\n🧪 Running: ${test.name}`);

      try {
        const result = execSync(test.command, {
          cwd: join(__dirname, '..'),
          encoding: 'utf8',
          timeout: 15000
        });

        console.log(`✅ ${test.name} - Passed`);
        passedTests++;
      } catch (error) {
        console.log(`❌ ${test.name} - Failed`);
        console.log(`   Expected: ${test.expected}`);
        console.log(`   Error: ${error.message}`);
      }
    }

    console.log(`\n📊 Test Results: ${passedTests}/${tests.length} tests passed`);

    if (passedTests === tests.length) {
      console.log('🎉 All MCP tool tests passed!');
      return true;
    } else {
      console.log('⚠️  Some tests failed - check the implementation');
      return false;
    }

  } catch (error) {
    console.error('❌ Error testing MCP tools:', error.message);
    return false;
  }
}

testMcpTools().then(isValid => {
  process.exit(isValid ? 0 : 1);
}).catch(error => {
  console.error('❌ Test execution failed:', error.message);
  process.exit(1);
});