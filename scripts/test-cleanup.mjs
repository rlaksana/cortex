#!/usr/bin/env node

/**
 * Cleanup Worker Test Runner
 *
 * Comprehensive test runner for the cleanup worker functionality.
 * Runs all test suites and provides detailed reports.
 */

import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

const testSuites = [
  {
    name: 'Cleanup Worker Service Unit Tests',
    pattern: 'src/services/__tests__/cleanup-worker.service.test.ts',
    description: 'Core cleanup worker functionality and business logic',
  },
  {
    name: 'MCP Tools Integration Tests',
    pattern: 'tests/integration/cleanup-mcp-tools.test.ts',
    description: 'MCP tool interface and end-to-end workflows',
  },
  {
    name: 'Cleanup Metrics Performance Tests',
    pattern: 'tests/performance/cleanup-metrics.test.ts',
    description: 'Performance and metrics accuracy under load',
  },
];

function runCommand(command, cwd = projectRoot) {
  try {
    console.log(`🔧 Running: ${command}`);
    const result = execSync(command, {
      cwd,
      stdio: 'inherit',
      env: {
        ...process.env,
        NODE_ENV: 'test',
      },
    });
    return { success: true, output: result };
  } catch (error) {
    console.error(`❌ Command failed: ${command}`);
    return { success: false, error };
  }
}

function printHeader(title) {
  console.log('\n' + '='.repeat(60));
  console.log(`🧪 ${title}`);
  console.log('='.repeat(60));
}

function printFooter() {
  console.log('\n' + '='.repeat(60));
  console.log('✨ Test run completed!');
  console.log('='.repeat(60));
}

async function runTestSuite(suite) {
  printHeader(suite.name);
  console.log(`📝 ${suite.description}`);
  console.log(`🔍 Pattern: ${suite.pattern}`);

  const testCommand = `npx jest ${suite.pattern} --verbose --coverage --coverageDirectory=coverage-cleanup`;

  const result = runCommand(testCommand);

  if (result.success) {
    console.log(`✅ ${suite.name} - PASSED`);
    return true;
  } else {
    console.log(`❌ ${suite.name} - FAILED`);
    return false;
  }
}

async function runSpecificTest(pattern) {
  printHeader('Running Specific Test');
  console.log(`🔍 Pattern: ${pattern}`);

  const testCommand = `npx jest ${pattern} --verbose`;
  const result = runCommand(testCommand);

  return result.success;
}

async function generateTestReport(results) {
  printHeader('Test Report Summary');

  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => r.failed).length;
  const total = results.length;

  console.log(`📊 Total Test Suites: ${total}`);
  console.log(`✅ Passed: ${passed}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`📈 Success Rate: ${((passed / total) * 100).toFixed(1)}%`);

  console.log('\n📋 Detailed Results:');
  results.forEach((result) => {
    const status = result.passed ? '✅' : '❌';
    console.log(`  ${status} ${result.name}`);
    if (!result.passed && result.error) {
      console.log(`     Error: ${result.error.message}`);
    }
  });

  if (failed > 0) {
    console.log('\n🔧 Failed tests to fix:');
    results
      .filter((r) => !r.passed)
      .forEach((result) => {
        console.log(`  - ${result.name}`);
      });
  }
}

function showUsage() {
  console.log(`
🧪 Cleanup Worker Test Runner

Usage:
  node scripts/test-cleanup.mjs [options]

Options:
  --help, -h           Show this help message
  --all, -a            Run all test suites (default)
  --service            Run only service unit tests
  --integration, -i    Run only integration tests
  --performance, -p    Run only performance tests
  --pattern <pattern>  Run tests matching specific pattern
  --coverage, -c       Generate coverage reports
  --watch, -w          Run tests in watch mode

Examples:
  node scripts/test-cleanup.mjs                    # Run all tests
  node scripts/test-cleanup.mjs --service         # Run service tests only
  node scripts/test-cleanup.mjs --pattern "**/*.test.ts"  # Run all test files
  node scripts/test-cleanup.mjs --coverage        # Run with coverage
`);
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    showUsage();
    return;
  }

  printHeader('Cleanup Worker Test Runner');

  const results = [];

  try {
    if (args.includes('--pattern')) {
      const patternIndex = args.indexOf('--pattern');
      const pattern = args[patternIndex + 1];

      if (!pattern) {
        console.error('❌ Pattern not specified after --pattern');
        process.exit(1);
      }

      const success = await runSpecificTest(pattern);
      process.exit(success ? 0 : 1);
    } else if (args.includes('--service')) {
      const success = await runTestSuite(testSuites[0]);
      process.exit(success ? 0 : 1);
    } else if (args.includes('--integration') || args.includes('-i')) {
      const success = await runTestSuite(testSuites[1]);
      process.exit(success ? 0 : 1);
    } else if (args.includes('--performance') || args.includes('-p')) {
      const success = await runTestSuite(testSuites[2]);
      process.exit(success ? 0 : 1);
    } else {
      // Run all test suites
      for (const suite of testSuites) {
        const success = await runTestSuite(suite);
        results.push({
          name: suite.name,
          passed: success,
          failed: !success,
        });
      }

      await generateTestReport(results);

      const allPassed = results.every((r) => r.passed);
      process.exit(allPassed ? 0 : 1);
    }
  } catch (error) {
    console.error('❌ Test runner failed:', error);
    process.exit(1);
  }
}

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Run main function
main().catch((error) => {
  console.error('❌ Test runner error:', error);
  process.exit(1);
});
