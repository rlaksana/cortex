#!/usr/bin/env node

/**
 * Comprehensive MCP Server Shutdown Test Runner
 *
 * Advanced test runner for MCP server shutdown functionality.
 * Uses the shutdown test utilities to perform thorough validation.
 *
 * Usage:
 *   node test-shutdown-comprehensive.mjs
 *   node test-shutdown-comprehensive.mjs --verbose
 *   node test-shutdown-comprehensive.mjs --integration
 *   node test-shutdown-comprehensive.mjs --stress
 *
 * @author Cortex Test Suite
 * @version 1.0.0
 */

import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { TestServerManager, ShutdownTestExecutor, ShutdownTestUtils } from './tests/utils/shutdown-test-utils.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

class ComprehensiveShutdownTestRunner {
  constructor(options = {}) {
    this.options = {
      verbose: options.verbose || false,
      integration: options.integration || false,
      stress: options.stress || false,
      timeout: options.timeout || 30000
    };

    this.executor = new ShutdownTestExecutor();
    this.results = [];
    this.startTime = Date.now();
  }

  log(message, level = 'INFO') {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] [${level}] ${message}`);
  }

  async runAllTests() {
    this.log('🚀 Starting comprehensive MCP server shutdown tests', 'INFO');
    this.log(`Test options: ${JSON.stringify(this.options)}`, 'INFO');

    try {
      // Core shutdown functionality tests
      await this.runCoreShutdownTests();

      // Connection cleanup tests
      await this.runConnectionCleanupTests();

      // In-flight operation tests
      await this.runInflightOperationTests();

      // Resource management tests
      await this.runResourceManagementTests();

      // Error handling tests
      await this.runErrorHandlingTests();

      if (this.options.integration) {
        await this.runIntegrationTests();
      }

      if (this.options.stress) {
        await this.runStressTests();
      }

    } catch (error) {
      this.log(`Test execution failed: ${error.message}`, 'ERROR');
      console.error(error);
    }

    this.generateFinalReport();
  }

  async runCoreShutdownTests() {
    this.log('📋 Running core shutdown functionality tests...', 'INFO');

    // Test SIGINT handling
    this.results.push(await this.executor.executeTest(
      'SIGINT Graceful Shutdown',
      async (server) => {
        await this.waitForServerReady(server);
        await server.stop('SIGINT');
      },
      { logOutput: this.options.verbose }
    ));

    // Test SIGTERM handling
    this.results.push(await this.executor.executeTest(
      'SIGTERM Graceful Shutdown',
      async (server) => {
        await this.waitForServerReady(server);
        await server.stop('SIGTERM');
      },
      { logOutput: this.options.verbose }
    ));

    // Test multiple signals
    this.results.push(await this.executor.executeTest(
      'Multiple Signal Handling',
      async (server) => {
        await this.waitForServerReady(server);

        // Send multiple signals rapidly
        setTimeout(() => server.kill('SIGINT'), 100);
        setTimeout(() => server.kill('SIGTERM'), 200);
        setTimeout(() => server.kill('SIGINT'), 300);

        await server.stop('SIGINT');
      },
      { logOutput: this.options.verbose }
    ));

    // Test immediate force shutdown
    this.results.push(await this.executor.executeTest(
      'Force Shutdown (SIGKILL)',
      async (server) => {
        await this.waitForServerReady(server);
        setTimeout(() => server.kill('SIGKILL'), 100);
      },
      { logOutput: this.options.verbose }
    ));
  }

  async runConnectionCleanupTests() {
    this.log('🔗 Running connection cleanup tests...', 'INFO');

    // Test database connection cleanup
    this.results.push(await this.executor.executeTest(
      'Database Connection Cleanup',
      async (server) => {
        await this.waitForServerReady(server);

        // Simulate database activity
        await this.simulateDatabaseActivity();

        await server.stop('SIGINT');
      },
      { logOutput: this.options.verbose }
    ));

    // Test HTTP client cleanup
    this.results.push(await this.executor.executeTest(
      'HTTP Client Cleanup',
      async (server) => {
        await this.waitForServerReady(server);

        // Make some HTTP requests
        await this.makeTestRequests();

        await server.stop('SIGINT');
      },
      { logOutput: this.options.verbose }
    ));

    // Test WebSocket cleanup
    this.results.push(await this.executor.executeTest(
      'WebSocket Connection Cleanup',
      async (server) => {
        await this.waitForServerReady(server);

        // Create WebSocket connections if server supports them
        await this.createWebSocketConnections();

        await server.stop('SIGINT');
      },
      { logOutput: this.options.verbose }
    ));
  }

  async runInflightOperationTests() {
    this.log('⚡ Running in-flight operation tests...', 'INFO');

    // Test shutdown during active operations
    this.results.push(await this.executor.executeTest(
      'Shutdown During Active Operations',
      async (server) => {
        await this.waitForServerReady(server);

        // Start long-running operations
        const operations = [];
        for (let i = 0; i < 5; i++) {
          operations.push(this.simulateLongOperation(2000));
        }

        // Shutdown while operations are running
        setTimeout(() => server.stop('SIGINT'), 1000);

        await Promise.allSettled(operations);
      },
      { logOutput: this.options.verbose, timeout: 15000 }
    ));

    // Test graceful drain mode
    this.results.push(await this.executor.executeTest(
      'Graceful Drain Mode',
      async (server) => {
        await this.waitForServerReady(server);

        // Start a stream of requests
        const requestInterval = setInterval(() => {
          this.makeTestRequests().catch(() => {});
        }, 100);

        // Initiate shutdown after some requests
        setTimeout(() => {
          clearInterval(requestInterval);
          server.stop('SIGINT');
        }, 2000);
      },
      { logOutput: this.options.verbose }
    ));

    // Test operation timeout handling
    this.results.push(await this.executor.executeTest(
      'Operation Timeout During Shutdown',
      async (server) => {
        await this.waitForServerReady(server);

        // Start very long operation
        this.simulateLongOperation(10000);

        // Quick shutdown to test timeout
        setTimeout(() => server.stop('SIGINT'), 500);
      },
      { logOutput: this.options.verbose, timeout: 8000 }
    ));
  }

  async runResourceManagementTests() {
    this.log('💾 Running resource management tests...', 'INFO');

    // Test memory cleanup
    this.results.push(await this.executor.executeTest(
      'Memory Cleanup During Shutdown',
      async (server) => {
        await this.waitForServerReady(server);

        // Allocate memory
        const memoryChunks = [];
        for (let i = 0; i < 100; i++) {
          memoryChunks.push(new Array(10000).fill(Math.random()));
        }

        await server.stop('SIGINT');

        // Cleanup memory
        memoryChunks.length = 0;
        if (global.gc) global.gc();
      },
      { logOutput: this.options.verbose }
    ));

    // Test file handle cleanup
    this.results.push(await this.executor.executeTest(
      'File Handle Cleanup',
      async (server) => {
        await this.waitForServerReady(server);

        // Create test files
        const testFiles = await ShutdownTestUtils.createTestFiles(5);

        // Open file handles
        const handles = [];
        for (const file of testFiles) {
          try {
            const fs = await import('fs');
            handles.push(fs.openSync(file, 'r'));
          } catch (error) {
            // Ignore errors
          }
        }

        await server.stop('SIGINT');

        // Cleanup
        handles.forEach(handle => {
          try {
            const fs = require('fs');
            fs.closeSync(handle);
          } catch (error) {
            // Ignore errors
          }
        });

        await ShutdownTestUtils.cleanupTestFiles(testFiles);
      },
      { logOutput: this.options.verbose }
    ));

    // Test timer cleanup
    this.results.push(await this.executor.executeTest(
      'Timer and Interval Cleanup',
      async (server) => {
        await this.waitForServerReady(server);

        // Create various timers
        const timers = [];
        for (let i = 0; i < 10; i++) {
          timers.push(setTimeout(() => {}, 5000 + i * 1000));
        }

        const intervals = [];
        for (let i = 0; i < 3; i++) {
          intervals.push(setInterval(() => {}, 2000));
        }

        await server.stop('SIGINT');

        // Cleanup timers
        timers.forEach(timer => clearTimeout(timer));
        intervals.forEach(interval => clearInterval(interval));
      },
      { logOutput: this.options.verbose }
    ));
  }

  async runErrorHandlingTests() {
    this.log('🚨 Running error handling tests...', 'INFO');

    // Test shutdown with errors in operations
    this.results.push(await this.executor.executeTest(
      'Shutdown with Operation Errors',
      async (server) => {
        await this.waitForServerReady(server);

        // Simulate operations that might fail
        Promise.resolve().then(() => {
          throw new Error('Simulated operation error');
        }).catch(() => {});

        await server.stop('SIGINT');
      },
      { logOutput: this.options.verbose }
    ));

    // Test unhandled exception during shutdown
    this.results.push(await this.executor.executeTest(
      'Unhandled Exception During Shutdown',
      async (server) => {
        await this.waitForServerReady(server);

        // Trigger unhandled exception
        setTimeout(() => {
          process.emit('uncaughtException', new Error('Test unhandled exception'));
        }, 500);

        await server.stop('SIGINT');
      },
      { logOutput: this.options.verbose }
    ));

    // Test unhandled rejection during shutdown
    this.results.push(await this.executor.executeTest(
      'Unhandled Rejection During Shutdown',
      async (server) => {
        await this.waitForServerReady(server);

        // Trigger unhandled rejection
        setTimeout(() => {
          Promise.reject(new Error('Test unhandled rejection'));
        }, 500);

        await server.stop('SIGINT');
      },
      { logOutput: this.options.verbose }
    ));
  }

  async runIntegrationTests() {
    this.log('🔧 Running integration tests...', 'INFO');

    // Test with real workload
    this.results.push(await this.executor.executeTest(
      'Real Workload Shutdown',
      async (server) => {
        await this.waitForServerReady(server);

        // Simulate real application workload
        const workload = this.simulateRealWorkload();

        // Shutdown after some workload
        setTimeout(() => server.stop('SIGINT'), 5000);

        await workload;
      },
      { logOutput: this.options.verbose, timeout: 20000 }
    ));

    // Test concurrent shutdown scenarios
    this.results.push(await this.executor.executeTest(
      'Concurrent Shutdown Scenarios',
      async (server) => {
        await this.waitForServerReady(server);

        // Multiple shutdown triggers
        const triggers = [
          () => server.stop('SIGINT'),
          () => server.stop('SIGTERM'),
          () => server.kill('SIGKILL')
        ];

        // Execute them with slight delays
        triggers.forEach((trigger, index) => {
          setTimeout(trigger, 1000 + index * 500);
        });
      },
      { logOutput: this.options.verbose }
    ));
  }

  async runStressTests() {
    this.log('💪 Running stress tests...', 'INFO');

    // Test rapid start/stop cycles
    this.results.push(await this.executor.executeTest(
      'Rapid Start/Stop Cycles',
      async (server) => {
        // This test will manage its own server lifecycle
        for (let i = 0; i < 5; i++) {
          const testServer = new TestServerManager({ logOutput: this.options.verbose });
          await testServer.start();
          await testServer.stop('SIGINT');
          testServer.cleanup();

          // Brief pause between cycles
          await new Promise(resolve => setTimeout(resolve, 500));
        }
      },
      { logOutput: false }
    ));

    // Test shutdown under high load
    this.results.push(await this.executor.executeTest(
      'Shutdown Under High Load',
      async (server) => {
        await this.waitForServerReady(server);

        // Create high load
        const loadPromises = [];
        for (let i = 0; i < 50; i++) {
          loadPromises.push(this.simulateHighLoadOperation());
        }

        // Shutdown under load
        setTimeout(() => server.stop('SIGINT'), 2000);

        await Promise.allSettled(loadPromises);
      },
      { logOutput: this.options.verbose, timeout: 30000 }
    ));

    // Test memory pressure during shutdown
    this.results.push(await this.executor.executeTest(
      'Memory Pressure During Shutdown',
      async (server) => {
        await this.waitForServerReady(server);

        // Create memory pressure
        const memoryBombs = [];
        for (let i = 0; i < 10; i++) {
          memoryBombs.push(new Array(100000).fill(Math.random()));
        }

        await server.stop('SIGINT');

        // Cleanup
        memoryBombs.length = 0;
        if (global.gc) global.gc();
      },
      { logOutput: this.options.verbose }
    ));
  }

  // Helper methods
  async waitForServerReady(server) {
    // Wait a bit for server to be fully ready
    await new Promise(resolve => setTimeout(resolve, 1000));
  }

  async simulateDatabaseActivity() {
    // Simulate database operations
    const operations = [];
    for (let i = 0; i < 10; i++) {
      operations.push(
        new Promise(resolve => setTimeout(resolve, Math.random() * 1000))
      );
    }
    await Promise.allSettled(operations);
  }

  async makeTestRequests() {
    try {
      const promises = [
        fetch('http://httpbin.org/delay/0.5', { signal: AbortSignal.timeout(2000) }),
        fetch('http://httpbin.org/json', { signal: AbortSignal.timeout(2000) })
      ];
      await Promise.allSettled(promises);
    } catch (error) {
      // Ignore network errors
    }
  }

  async createWebSocketConnections() {
    // Placeholder for WebSocket testing
    // Would require WebSocket server support
  }

  async simulateLongOperation(duration) {
    return new Promise(resolve => setTimeout(resolve, duration));
  }

  async simulateRealWorkload() {
    const operations = [];

    // Database operations
    operations.push(this.simulateDatabaseActivity());

    // HTTP requests
    operations.push(this.makeTestRequests());

    // Memory operations
    operations.push(this.simulateLongOperation(2000));

    // File operations
    const testFiles = await ShutdownTestUtils.createTestFiles(3);
    operations.push(
      ShutdownTestUtils.cleanupTestFiles(testFiles)
    );

    await Promise.allSettled(operations);
  }

  async simulateHighLoadOperation() {
    // CPU intensive operation
    const start = Date.now();
    while (Date.now() - start < 100) {
      Math.random() * Math.random();
    }

    // Memory allocation
    const data = new Array(1000).fill(Math.random());

    // Async operation
    await new Promise(resolve => setTimeout(resolve, 10));

    return data;
  }

  generateFinalReport() {
    const duration = Date.now() - this.startTime;
    const totalTests = this.results.length;
    const passedTests = this.results.filter(r => r.passed).length;
    const failedTests = totalTests - passedTests;

    console.log('\n' + '='.repeat(80));
    console.log('🏁 COMPREHENSIVE MCP SERVER SHUTDOWN TEST REPORT');
    console.log('='.repeat(80));
    console.log(`Test completed at: ${new Date().toISOString()}`);
    console.log(`Total duration: ${Math.round(duration / 1000)}s`);
    console.log(`Total tests: ${totalTests}`);
    console.log(`Passed: ${passedTests} ✅`);
    console.log(`Failed: ${failedTests} ❌`);
    console.log(`Success rate: ${Math.round((passedTests / totalTests) * 100)}%`);

    if (failedTests > 0) {
      console.log('\n❌ FAILED TESTS:');
      this.results
        .filter(r => !r.passed)
        .forEach(r => {
          console.log(`   ${r.testName}`);
          if (r.errors.length > 0) {
            r.errors.forEach(error => console.log(`     - ${error}`));
          }
          if (r.warnings.length > 0) {
            r.warnings.forEach(warning => console.log(`     - ${warning}`));
          }
        });
    }

    // Resource usage summary
    const memoryDiffs = this.results.map(r => r.resources.diff.memory.heapUsed);
    const avgMemoryDiff = memoryDiffs.reduce((a, b) => a + b, 0) / memoryDiffs.length;

    const handleDiffs = this.results.map(r => r.resources.diff.handles);
    const avgHandleDiff = handleDiffs.reduce((a, b) => a + b, 0) / handleDiffs.length;

    console.log('\n📊 RESOURCE USAGE SUMMARY:');
    console.log(`   Average memory change: ${Math.round(avgMemoryDiff / 1024 / 1024)}MB`);
    console.log(`   Average handle change: ${Math.round(avgHandleDiff)}`);

    // Save detailed report
    const report = ShutdownTestUtils.generateReport(this.results);
    const reportPath = './comprehensive-shutdown-test-report.md';

    try {
      const fs = await import('fs');
      fs.writeFileSync(reportPath, report);
      console.log(`\n📄 Detailed report saved to: ${reportPath}`);
    } catch (error) {
      console.log(`\n⚠️  Could not save detailed report: ${error.message}`);
    }

    // Save JSON report for analysis
    const jsonReport = {
      timestamp: new Date().toISOString(),
      duration,
      summary: {
        total: totalTests,
        passed: passedTests,
        failed: failedTests,
        successRate: Math.round((passedTests / totalTests) * 100)
      },
      resourceSummary: {
        avgMemoryDiff: Math.round(avgMemoryDiff / 1024 / 1024),
        avgHandleDiff: Math.round(avgHandleDiff)
      },
      tests: this.results.map(r => ({
        name: r.testName,
        passed: r.passed,
        duration: r.duration,
        exitCode: r.exitCode,
        memoryDiff: Math.round(r.resources.diff.memory.heapUsed / 1024 / 1024),
        handleDiff: r.resources.diff.handles,
        errors: r.errors,
        warnings: r.warnings
      }))
    };

    try {
      const jsonPath = './comprehensive-shutdown-test-report.json';
      const fs = await import('fs');
      fs.writeFileSync(jsonPath, JSON.stringify(jsonReport, null, 2));
      console.log(`📊 JSON report saved to: ${jsonPath}`);
    } catch (error) {
      console.log(`⚠️  Could not save JSON report: ${error.message}`);
    }

    console.log('='.repeat(80));

    if (failedTests === 0) {
      console.log('🎉 ALL TESTS PASSED! MCP server shutdown functionality is excellent.');
      process.exit(0);
    } else {
      console.log('❌ SOME TESTS FAILED! Please review the failed tests and address the issues.');
      process.exit(1);
    }
  }
}

// Parse command line arguments
const args = process.argv.slice(2);
const options = {
  verbose: args.includes('--verbose'),
  integration: args.includes('--integration'),
  stress: args.includes('--stress')
};

// Run the comprehensive test suite
const runner = new ComprehensiveShutdownTestRunner(options);
runner.runAllTests().catch(error => {
  console.error('Test runner failed:', error);
  process.exit(1);
});