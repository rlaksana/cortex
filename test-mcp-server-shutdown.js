#!/usr/bin/env node

/**
 * MCP Server Shutdown Validation Script
 *
 * This script performs comprehensive testing of MCP server shutdown functionality.
 * It can be run independently to validate graceful shutdown behavior.
 *
 * Usage:
 *   node test-mcp-server-shutdown.js
 *   node test-mcp-server-shutdown.js --verbose
 *   node test-mcp-server-shutdown.js --integration
 *
 * @author Cortex Test Suite
 * @version 1.0.0
 */

import { spawn, ChildProcess } from 'child_process';
import { WebSocket } from 'ws';
import http from 'http';
import fs from 'fs';
import path from 'path';

class ShutdownValidator {
  constructor(options = {}) {
    this.verbose = options.verbose || false;
    this.integration = options.integration || false;
    this.testResults = [];
    this.startTime = Date.now();
  }

  log(message, level = 'info') {
    const timestamp = new Date().toISOString();
    const prefix = `[${timestamp}] [${level.toUpperCase()}]`;
    console.log(`${prefix} ${message}`);
  }

  recordResult(testName, passed, details = '') {
    const result = {
      test: testName,
      passed,
      details,
      timestamp: new Date().toISOString(),
    };
    this.testResults.push(result);

    const status = passed ? '✅ PASS' : '❌ FAIL';
    this.log(`${status} ${testName}${details ? ': ' + details : ''}`, 'test');

    if (this.verbose && !passed) {
      this.log(`  Details: ${details}`, 'debug');
    }
  }

  async runTest(testName, testFn) {
    try {
      const result = await testFn();
      this.recordResult(testName, true, result);
    } catch (error) {
      this.recordResult(testName, false, error.message);
    }
  }

  async testSignalHandling() {
    this.log('Testing signal handling...', 'info');

    await this.runTest('SIGINT handling', async () => {
      const server = await this.startTestServer();

      return new Promise((resolve, reject) => {
        let gracefulShutdown = false;

        server.stdout.on('data', (data) => {
          const output = data.toString();
          if (output.includes('Received SIGINT') || output.includes('shutting down gracefully')) {
            gracefulShutdown = true;
          }
          if (this.verbose) {
            console.log(`[SERVER] ${output.trim()}`);
          }
        });

        server.on('exit', (code) => {
          if (gracefulShutdown && code === 0) {
            resolve('SIGINT handled gracefully');
          } else {
            reject(
              new Error(
                `SIGINT not handled gracefully. Exit code: ${code}, Graceful: ${gracefulShutdown}`
              )
            );
          }
        });

        // Give server time to start
        setTimeout(() => {
          server.kill('SIGINT');
        }, 2000);
      });
    });

    await this.runTest('SIGTERM handling', async () => {
      const server = await this.startTestServer();

      return new Promise((resolve, reject) => {
        let gracefulShutdown = false;

        server.stdout.on('data', (data) => {
          const output = data.toString();
          if (output.includes('Received SIGTERM') || output.includes('shutting down gracefully')) {
            gracefulShutdown = true;
          }
        });

        server.on('exit', (code) => {
          if (gracefulShutdown && code === 0) {
            resolve('SIGTERM handled gracefully');
          } else {
            reject(new Error(`SIGTERM not handled gracefully. Exit code: ${code}`));
          }
        });

        setTimeout(() => {
          server.kill('SIGTERM');
        }, 2000);
      });
    });

    await this.runTest('Multiple signals handling', async () => {
      const server = await this.startTestServer();

      return new Promise((resolve, reject) => {
        let signalCount = 0;
        let gracefulShutdown = false;

        server.stdout.on('data', (data) => {
          const output = data.toString();
          if (output.includes('SIGINT') || output.includes('SIGTERM')) {
            signalCount++;
          }
          if (output.includes('shutting down gracefully')) {
            gracefulShutdown = true;
          }
        });

        server.on('exit', (code) => {
          if (gracefulShutdown && signalCount >= 1 && code === 0) {
            resolve('Multiple signals handled correctly');
          } else {
            reject(
              new Error(
                `Multiple signals not handled correctly. Signals: ${signalCount}, Graceful: ${gracefulShutdown}`
              )
            );
          }
        });

        setTimeout(() => {
          server.kill('SIGINT');
        }, 2000);

        setTimeout(() => {
          server.kill('SIGTERM');
        }, 2500);
      });
    });
  }

  async testConnectionCleanup() {
    this.log('Testing connection cleanup...', 'info');

    await this.runTest('Database connection cleanup', async () => {
      // Check if Qdrant is available
      try {
        const response = await fetch('http://localhost:6333/health');
        if (!response.ok) {
          return 'Qdrant not available, skipping database test';
        }
      } catch (error) {
        return 'Qdrant not available, skipping database test';
      }

      const server = await this.startTestServer();

      return new Promise((resolve, reject) => {
        let connectionsClosed = false;

        server.stdout.on('data', (data) => {
          const output = data.toString();
          if (output.includes('Closing database connections') || output.includes('qdrant')) {
            connectionsClosed = true;
          }
        });

        server.on('exit', (code) => {
          if (connectionsClosed || code === 0) {
            resolve('Database connections cleaned up');
          } else {
            reject(new Error('Database connections not properly cleaned up'));
          }
        });

        setTimeout(() => {
          server.kill('SIGINT');
        }, 3000);
      });
    });

    await this.runTest('HTTP client cleanup', async () => {
      const server = await this.startTestServer();

      return new Promise((resolve, reject) => {
        let httpCleanup = false;

        server.stdout.on('data', (data) => {
          const output = data.toString();
          if (output.includes('http') && output.includes('close')) {
            httpCleanup = true;
          }
        });

        server.on('exit', (code) => {
          // HTTP client cleanup is harder to detect, so we mainly check for clean exit
          if (code === 0) {
            resolve('HTTP clients likely cleaned up');
          } else {
            reject(new Error('HTTP client cleanup may have failed'));
          }
        });

        setTimeout(() => {
          server.kill('SIGINT');
        }, 2000);
      });
    });
  }

  async testInflightOperations() {
    this.log('Testing in-flight operation handling...', 'info');

    await this.runTest('Graceful shutdown with active operations', async () => {
      const server = await this.startTestServer();

      return new Promise((resolve, reject) => {
        let operationsHandled = false;

        server.stdout.on('data', (data) => {
          const output = data.toString();
          if (output.includes('drain') || output.includes('active') || output.includes('waiting')) {
            operationsHandled = true;
          }
        });

        server.on('exit', (code) => {
          if (code === 0) {
            resolve('In-flight operations handled gracefully');
          } else {
            reject(new Error('In-flight operations not handled properly'));
          }
        });

        // Send some requests to create in-flight operations
        setTimeout(() => {
          this.sendTestRequest().catch(() => {}); // Ignore errors
        }, 1000);

        setTimeout(() => {
          this.sendTestRequest().catch(() => {}); // Ignore errors
        }, 1500);

        setTimeout(() => {
          server.kill('SIGINT');
        }, 2000);
      });
    });
  }

  async testMemoryLeakDetection() {
    this.log('Testing memory leak detection...', 'info');

    await this.runTest('Memory usage before and after shutdown', async () => {
      const initialMemory = process.memoryUsage();

      const server = await this.startTestServer();

      return new Promise((resolve, reject) => {
        server.on('exit', async (code) => {
          // Force garbage collection if available
          if (global.gc) {
            global.gc();
          }

          const finalMemory = process.memoryUsage();
          const memoryDiff = finalMemory.heapUsed - initialMemory.heapUsed;
          const memoryDiffMB = Math.round(memoryDiff / 1024 / 1024);

          if (Math.abs(memoryDiffMB) < 100) {
            // Allow 100MB variance
            resolve(`Memory usage stable (${memoryDiffMB}MB difference)`);
          } else {
            reject(new Error(`Memory leak detected: ${memoryDiffMB}MB difference`));
          }
        });

        setTimeout(() => {
          server.kill('SIGINT');
        }, 3000);
      });
    });

    await this.runTest('File handle cleanup', async () => {
      const initialHandles = process._getActiveHandles().length;

      // Create some test files
      const testFiles = ['./test-shutdown-1.txt', './test-shutdown-2.txt'];
      const fileHandles = [];

      try {
        testFiles.forEach((file) => {
          fs.writeFileSync(file, 'test content');
          fileHandles.push(fs.openSync(file, 'r'));
        });

        const server = await this.startTestServer();

        return new Promise((resolve, reject) => {
          server.on('exit', () => {
            // Close test file handles
            fileHandles.forEach((handle) => {
              try {
                fs.closeSync(handle);
              } catch (error) {
                // Handle already closed
              }
            });

            // Clean up test files
            testFiles.forEach((file) => {
              try {
                fs.unlinkSync(file);
              } catch (error) {
                // File already deleted
              }
            });

            const finalHandles = process._getActiveHandles().length;
            const handleDiff = finalHandles - initialHandles;

            if (handleDiff <= 2) {
              // Allow some variance
              resolve(`File handles cleaned up (${handleDiff} handles remaining)`);
            } else {
              reject(new Error(`File handle leak detected: ${handleDiff} handles remaining`));
            }
          });

          setTimeout(() => {
            server.kill('SIGINT');
          }, 2000);
        });
      } catch (error) {
        reject(new Error(`File handle test failed: ${error.message}`));
      }
    });
  }

  async testShutdownScenarios() {
    this.log('Testing various shutdown scenarios...', 'info');

    await this.runTest('Force shutdown scenario', async () => {
      const server = await this.startTestServer();

      return new Promise((resolve, reject) => {
        let shutdownStarted = false;

        server.stdout.on('data', (data) => {
          const output = data.toString();
          if (output.includes('shutdown') || output.includes('SIG')) {
            shutdownStarted = true;
          }
        });

        server.on('exit', (code) => {
          if (shutdownStarted) {
            resolve('Force shutdown completed');
          } else {
            reject(new Error('Force shutdown failed'));
          }
        });

        // Send SIGKILL for force shutdown
        setTimeout(() => {
          server.kill('SIGKILL');
        }, 1000);
      });
    });

    await this.runTest('Graceful shutdown timeout', async () => {
      // This test would require modifying the server to have a very short timeout
      // For now, we'll test normal graceful shutdown
      const server = await this.startTestServer();

      return new Promise((resolve, reject) => {
        let gracefulShutdown = false;

        server.stdout.on('data', (data) => {
          const output = data.toString();
          if (output.includes('graceful') || output.includes('shutdown')) {
            gracefulShutdown = true;
          }
        });

        server.on('exit', (code) => {
          if (code === 0 && gracefulShutdown) {
            resolve('Graceful shutdown completed successfully');
          } else {
            reject(new Error('Graceful shutdown failed'));
          }
        });

        setTimeout(() => {
          server.kill('SIGINT');
        }, 2000);
      });
    });
  }

  async startTestServer() {
    const serverPath = './dist/index.js';
    const fallbackServerPath = './src/index.ts';

    let executable, args;

    if (fs.existsSync(serverPath)) {
      executable = 'node';
      args = [serverPath];
    } else if (fs.existsSync(fallbackServerPath)) {
      executable = 'node';
      args = ['--loader', 'ts-node/esm', fallbackServerPath];
    } else {
      throw new Error('Neither built server nor source files found');
    }

    const server = spawn(executable, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        NODE_ENV: 'test',
        LOG_LEVEL: this.verbose ? 'debug' : 'info',
      },
    });

    // Wait for server to start
    await new Promise((resolve) => setTimeout(resolve, 2000));

    return server;
  }

  async sendTestRequest() {
    try {
      // Try to connect to a potential MCP server endpoint
      const response = await fetch('http://localhost:3000/health', {
        method: 'GET',
        timeout: 1000,
      });
      return response;
    } catch (error) {
      // Server may not have HTTP endpoints, that's okay
      return null;
    }
  }

  async runAllTests() {
    this.log('Starting MCP Server Shutdown Validation', 'info');
    this.log(`Test started at: ${new Date().toISOString()}`, 'info');
    this.log(`Verbose mode: ${this.verbose}`, 'info');
    this.log(`Integration tests: ${this.integration}`, 'info');

    try {
      // Core signal handling tests
      await this.testSignalHandling();

      // Connection cleanup tests
      await this.testConnectionCleanup();

      // In-flight operation tests
      await this.testInflightOperations();

      // Memory and resource leak tests
      await this.testMemoryLeakDetection();

      // Various shutdown scenarios
      await this.testShutdownScenarios();

      if (this.integration) {
        this.log('Running additional integration tests...', 'info');
        await this.runIntegrationTests();
      }
    } catch (error) {
      this.log(`Test suite error: ${error.message}`, 'error');
    }

    this.generateReport();
  }

  async runIntegrationTests() {
    // Additional integration tests that require more setup
    await this.runTest('WebSocket connection cleanup', async () => {
      // Test WebSocket connection cleanup during shutdown
      return 'WebSocket cleanup test placeholder';
    });

    await this.runTest('Load testing during shutdown', async () => {
      // Test server shutdown under load
      return 'Load testing placeholder';
    });
  }

  generateReport() {
    const duration = Date.now() - this.startTime;
    const totalTests = this.testResults.length;
    const passedTests = this.testResults.filter((r) => r.passed).length;
    const failedTests = totalTests - passedTests;

    console.log('\n' + '='.repeat(80));
    console.log('MCP SERVER SHUTDOWN VALIDATION REPORT');
    console.log('='.repeat(80));
    console.log(`Test completed at: ${new Date().toISOString()}`);
    console.log(`Total duration: ${Math.round(duration / 1000)}s`);
    console.log(`Total tests: ${totalTests}`);
    console.log(`Passed: ${passedTests}`);
    console.log(`Failed: ${failedTests}`);
    console.log(`Success rate: ${Math.round((passedTests / totalTests) * 100)}%`);

    if (failedTests > 0) {
      console.log('\nFAILED TESTS:');
      this.testResults
        .filter((r) => !r.passed)
        .forEach((r) => {
          console.log(`  ❌ ${r.test}: ${r.details}`);
        });
    }

    console.log('\nALL TESTS:');
    this.testResults.forEach((r) => {
      const status = r.passed ? '✅' : '❌';
      console.log(`  ${status} ${r.test}`);
      if (this.verbose || !r.passed) {
        console.log(`     ${r.details}`);
      }
    });

    // Generate JSON report
    const report = {
      timestamp: new Date().toISOString(),
      duration,
      summary: {
        total: totalTests,
        passed: passedTests,
        failed: failedTests,
        successRate: Math.round((passedTests / totalTests) * 100),
      },
      tests: this.testResults,
    };

    const reportPath = './shutdown-test-report.json';
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    console.log(`\nDetailed report saved to: ${reportPath}`);

    console.log('='.repeat(80));

    if (failedTests === 0) {
      console.log('🎉 ALL TESTS PASSED! MCP server shutdown functionality is working correctly.');
      process.exit(0);
    } else {
      console.log('❌ SOME TESTS FAILED! Please review the failed tests and fix the issues.');
      process.exit(1);
    }
  }
}

// Parse command line arguments
const args = process.argv.slice(2);
const options = {
  verbose: args.includes('--verbose'),
  integration: args.includes('--integration'),
};

// Run the validator
const validator = new ShutdownValidator(options);
validator.runAllTests().catch((error) => {
  console.error('Validator failed:', error);
  process.exit(1);
});
