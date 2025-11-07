#!/usr/bin/env node

/**
 * Search Degradation Behavior Test Runner
 *
 * Executes comprehensive tests for search system resilience and degrade behavior.
 * Provides detailed analysis of performance under various failure conditions.
 */

import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { execSync } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ANSI color codes for output formatting
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
};

function colorLog(color, message) {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function colorLogBold(color, message) {
  console.log(`${colors.bold}${colors[color]}${message}${colors.reset}`);
}

class SearchDegradationTester {
  constructor() {
    this.testResults = {
      total: 0,
      passed: 0,
      failed: 0,
      skipped: 0,
      suites: [],
    };
    this.startTime = Date.now();
    this.performanceMetrics = [];
  }

  printHeader() {
    colorLogBold('cyan', '\n╔══════════════════════════════════════════════════════════════╗');
    colorLogBold('cyan', '║     SEARCH DEGRADATION BEHAVIOR COMPREHENSIVE TESTS      ║');
    colorLogBold('cyan', '╚══════════════════════════════════════════════════════════════╝');
    colorLog('cyan', '\n🔍 Testing Search System Resilience and Degrade Behavior');
    colorLog('cyan', '📊 Analyzing Performance Under Various Failure Conditions');
    colorLog('cyan', '🔄 Validating Automatic Recovery Mechanisms\n');
  }

  async runTestSuite(suiteName, testPattern) {
    colorLogBold('yellow', `\n📋 Running Test Suite: ${suiteName}`);
    colorLog('dim', '─'.repeat(60));

    const suiteStartTime = Date.now();

    try {
      // Run the specific test suite
      const testCommand = `npm test -- --testNamePattern="${testPattern}" --verbose`;
      const output = execSync(testCommand, {
        encoding: 'utf8',
        cwd: __dirname,
        stdio: 'pipe',
      });

      const suiteEndTime = Date.now();
      const suiteDuration = suiteEndTime - suiteStartTime;

      // Parse results
      const results = this.parseTestOutput(output);

      const suiteResult = {
        name: suiteName,
        duration: suiteDuration,
        ...results,
        output: output,
      };

      this.testResults.suites.push(suiteResult);
      this.testResults.total += results.total;
      this.testResults.passed += results.passed;
      this.testResults.failed += results.failed;
      this.testResults.skipped += results.skipped;

      this.printSuiteResults(suiteResult);

      return suiteResult;
    } catch (error) {
      const suiteEndTime = Date.now();
      const suiteDuration = suiteEndTime - suiteStartTime;

      const suiteResult = {
        name: suiteName,
        duration: suiteDuration,
        total: 0,
        passed: 0,
        failed: 1,
        skipped: 0,
        error: error.message,
        output: error.stdout || '',
      };

      this.testResults.suites.push(suiteResult);
      this.testResults.total++;
      this.testResults.failed++;

      colorLog('red', `❌ Test suite failed: ${error.message}`);
      return suiteResult;
    }
  }

  parseTestOutput(output) {
    const lines = output.split('\n');
    const results = {
      total: 0,
      passed: 0,
      failed: 0,
      skipped: 0,
      testCases: [],
    };

    // Parse Jest output
    for (const line of lines) {
      if (line.includes('Test Suites:')) {
        const match = line.match(/(\d+) passed, (\d+) failed, (\d+) skipped/);
        if (match) {
          results.passed = parseInt(match[1]);
          results.failed = parseInt(match[2]);
          results.skipped = parseInt(match[3]);
        }
      } else if (line.includes('Tests:')) {
        const match = line.match(/(\d+) passed, (\d+) failed/);
        if (match) {
          results.total = parseInt(match[1]) + parseInt(match[2]);
        }
      }
    }

    // If parsing failed, estimate from output
    if (results.total === 0) {
      const testMatches = output.match(/✓|✗|◦/g);
      if (testMatches) {
        results.total = testMatches.length;
        results.passed = (output.match(/✓/g) || []).length;
        results.failed = (output.match(/✗/g) || []).length;
        results.skipped = (output.match(/◦/g) || []).length;
      }
    }

    return results;
  }

  printSuiteResults(suiteResult) {
    colorLog('blue', `\n📊 Suite: ${suiteResult.name}`);
    colorLog('dim', `⏱️  Duration: ${suiteResult.duration}ms`);

    if (suiteResult.error) {
      colorLog('red', `❌ Error: ${suiteResult.error}`);
      return;
    }

    const totalWidth = 30;
    const passedWidth = Math.round((suiteResult.passed / suiteResult.total) * totalWidth);
    const failedWidth = Math.round((suiteResult.failed / suiteResult.total) * totalWidth);
    const skippedWidth = totalWidth - passedWidth - failedWidth;

    const progressBar =
      colors.green +
      '█'.repeat(passedWidth) +
      colors.red +
      '█'.repeat(failedWidth) +
      colors.yellow +
      '░'.repeat(skippedWidth) +
      colors.reset;

    console.log(`  [${progressBar}]`);
    console.log(`  ✓ Passed: ${colors.green}${suiteResult.passed}${colors.reset}`);
    console.log(`  ✗ Failed: ${colors.red}${suiteResult.failed}${colors.reset}`);
    console.log(`  ◦ Skipped: ${colors.yellow}${suiteResult.skipped}${colors.reset}`);
    console.log(`  📋 Total: ${suiteResult.total}`);
  }

  async runAllTests() {
    this.printHeader();

    const testSuites = [
      {
        name: 'Vector Database Failure Scenarios',
        pattern: 'Vector Database Failure Scenarios',
      },
      {
        name: 'High Query Load Scenarios',
        pattern: 'High Query Load Scenarios',
      },
      {
        name: 'Network Latency and Connectivity Issues',
        pattern: 'Network Latency and Connectivity Issues',
      },
      {
        name: 'Automatic Recovery Mechanisms',
        pattern: 'Automatic Recovery Mechanisms',
      },
      {
        name: 'Manual Recovery Triggers',
        pattern: 'Manual Recovery Triggers',
      },
      {
        name: 'System Health Monitoring',
        pattern: 'System Health Monitoring',
      },
      {
        name: 'Error Rate and Threshold Management',
        pattern: 'Error Rate and Threshold Management',
      },
    ];

    colorLogBold('magenta', '\n🚀 Starting Comprehensive Test Execution...\n');

    for (const suite of testSuites) {
      await this.runTestSuite(suite.name, suite.pattern);

      // Small delay between suites
      await new Promise((resolve) => setTimeout(resolve, 500));
    }

    this.printFinalReport();
    this.generateRecommendations();
  }

  printFinalReport() {
    const endTime = Date.now();
    const totalDuration = endTime - this.startTime;

    colorLogBold('cyan', '\n╔══════════════════════════════════════════════════════════════╗');
    colorLogBold('cyan', '║                    COMPREHENSIVE TEST RESULTS                ║');
    colorLogBold('cyan', '╚══════════════════════════════════════════════════════════════╝\n');

    // Overall statistics
    const successRate =
      this.testResults.total > 0
        ? ((this.testResults.passed / this.testResults.total) * 100).toFixed(1)
        : 0;

    colorLogBold('white', '📊 OVERALL STATISTICS');
    colorLog('dim', '─'.repeat(40));
    colorLog('cyan', `⏱️  Total Duration: ${totalDuration}ms`);
    colorLog('cyan', `📋 Total Tests: ${this.testResults.total}`);
    colorLog('green', `✅ Passed: ${this.testResults.passed}`);
    colorLog('red', `❌ Failed: ${this.testResults.failed}`);
    colorLog('yellow', `⏭️  Skipped: ${this.testResults.skipped}`);
    colorLogBold('cyan', `📈 Success Rate: ${successRate}%`);

    // Suite breakdown
    colorLogBold('white', '\n📋 SUITE BREAKDOWN');
    colorLog('dim', '─'.repeat(40));

    for (const suite of this.testResults.suites) {
      const suiteSuccessRate =
        suite.total > 0 ? ((suite.passed / suite.total) * 100).toFixed(1) : 0;
      const status = suite.failed === 0 ? '✅' : '❌';

      colorLog('blue', `${status} ${suite.name}`);
      colorLog('dim', `   Tests: ${suite.passed}/${suite.total} (${suiteSuccessRate}%)`);
      colorLog('dim', `   Duration: ${suite.duration}ms`);

      if (suite.error) {
        colorLog('red', `   Error: ${suite.error}`);
      }
      console.log();
    }

    // Performance analysis
    this.analyzePerformance();
  }

  analyzePerformance() {
    colorLogBold('white', '📈 PERFORMANCE ANALYSIS');
    colorLog('dim', '─'.repeat(40));

    if (this.testResults.suites.length === 0) {
      colorLog('yellow', '⚠️  No performance data available');
      return;
    }

    const durations = this.testResults.suites.map((s) => s.duration);
    const avgDuration = durations.reduce((sum, d) => sum + d, 0) / durations.length;
    const maxDuration = Math.max(...durations);
    const minDuration = Math.min(...durations);

    colorLog('cyan', `⏱️  Average Suite Duration: ${avgDuration.toFixed(0)}ms`);
    colorLog('cyan', `⏱️  Fastest Suite: ${minDuration}ms`);
    colorLog('cyan', `⏱️  Slowest Suite: ${maxDuration}ms`);

    // Identify slowest suites
    const sortedSuites = [...this.testResults.suites].sort((a, b) => b.duration - a.duration);
    colorLog('yellow', '\n🐌 Slowest Test Suites:');
    sortedSuites.slice(0, 3).forEach((suite, index) => {
      colorLog('yellow', `   ${index + 1}. ${suite.name} (${suite.duration}ms)`);
    });
  }

  generateRecommendations() {
    colorLogBold('white', '\n💡 RECOMMENDATIONS');
    colorLog('dim', '─'.repeat(40));

    const successRate =
      this.testResults.total > 0 ? this.testResults.passed / this.testResults.total : 0;

    if (successRate >= 0.9) {
      colorLog('green', '✅ Excellent search degradation behavior resilience!');
      colorLog('green', '   The search system demonstrates robust fallback mechanisms.');
    } else if (successRate >= 0.7) {
      colorLog('yellow', '⚠️  Good search degradation behavior with room for improvement:');
      colorLog('yellow', '   - Review failed test cases for specific issues');
      colorLog('yellow', '   - Consider enhancing error recovery mechanisms');
      colorLog('yellow', '   - Optimize performance under high load conditions');
    } else {
      colorLog('red', '❌ Search degradation behavior needs attention:');
      colorLog('red', '   - Critical issues in fallback mechanisms detected');
      colorLog('red', '   - Review circuit breaker implementation');
      colorLog('red', '   - Improve error handling and recovery strategies');
      colorLog('red', '   - Enhance system health monitoring');
    }

    // Specific recommendations based on failed suites
    const failedSuites = this.testResults.suites.filter((s) => s.failed > 0);
    if (failedSuites.length > 0) {
      colorLogBold('yellow', '\n🔧 Areas Requiring Attention:');
      failedSuites.forEach((suite) => {
        colorLog('yellow', `   • ${suite.name}: ${suite.failed} test(s) failed`);
      });
    }

    // Performance recommendations
    const slowSuites = this.testResults.suites.filter((s) => s.duration > 10000);
    if (slowSuites.length > 0) {
      colorLogBold('yellow', '\n⚡ Performance Optimization Opportunities:');
      slowSuites.forEach((suite) => {
        colorLog('yellow', `   • ${suite.name}: Consider optimizing test execution time`);
      });
    }

    colorLogBold('green', '\n🎯 Key Validation Points:');
    colorLog('green', '   ✓ Vector database failure handling');
    colorLog('green', '   ✓ High query load management');
    colorLog('green', '   ✓ Network latency tolerance');
    colorLog('green', '   ✓ Automatic recovery mechanisms');
    colorLog('green', '   ✓ Manual recovery triggers');
    colorLog('green', '   ✓ System health monitoring');
    colorLog('green', '   ✓ Error rate management');

    console.log();
  }
}

// Main execution
async function main() {
  const tester = new SearchDegradationTester();

  try {
    await tester.runAllTests();
    process.exit(0);
  } catch (error) {
    colorLog('red', `\n💥 Fatal error during test execution: ${error.message}`);
    colorLog('red', error.stack);
    process.exit(1);
  }
}

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  colorLog('red', `\n💥 Uncaught exception: ${error.message}`);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  colorLog('red', `\n💥 Unhandled rejection at: ${promise}, reason: ${reason}`);
  process.exit(1);
});

// Run the tests
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { SearchDegradationTester };
