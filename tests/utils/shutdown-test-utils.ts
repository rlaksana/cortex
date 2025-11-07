/**
 * Shutdown Test Utilities
 *
 * Utility functions and helpers for testing MCP server shutdown functionality.
 * Provides tools for process management, resource monitoring, and validation.
 *
 * @author Cortex Test Suite
 * @version 1.0.0
 */

import { spawn, ChildProcess } from 'child_process';
import { EventEmitter } from 'events';
import fs from 'fs';
import path from 'path';
import { performance } from 'perf_hooks';

export interface TestServerOptions {
  serverPath?: string;
  env?: Record<string, string>;
  args?: string[];
  timeout?: number;
  logOutput?: boolean;
}

export interface ResourceSnapshot {
  timestamp: number;
  memory: NodeJS['M']emoryUsage;
  handles: number;
  requests: number;
  cpuUsage: NodeJS['C']puUsage;
  openFiles?: string[];
}

export interface ShutdownTestResult {
  testName: string;
  passed: boolean;
  duration: number;
  exitCode: number | null;
  signal: string | null;
  output: string[];
  resources: {
    before: ResourceSnapshot;
    after: ResourceSnapshot;
    diff: {
      memory: {
        heapUsed: number;
        heapTotal: number;
        external: number;
        rss: number;
      };
      handles: number;
      requests: number;
    };
  };
  errors: string[];
  warnings: string[];
}

/**
 * Test server manager for spawning and controlling MCP server instances
 */
export class TestServerManager extends EventEmitter {
  private process: ChildProcess | null = null;
  private output: string[] = [];
  private startTime: number = 0;
  private endTime: number = 0;

  constructor(private options: TestServerOptions = {}) {
    super();
  }

  /**
   * Start a test server instance
   */
  async start(): Promise<void> {
    const serverPath = this.options.serverPath || this.findServerPath();
    if (!serverPath) {
      throw new Error('Server executable not found');
    }

    const args = this.options.args || this.getArgsForServer(serverPath);
    const env = {
      ...process.env,
      NODE_ENV: 'test',
      LOG_LEVEL: this.options.logOutput ? 'debug' : 'info',
      ...this.options.env,
    };

    this.process = spawn('node', [serverPath, ...args], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env,
    });

    this.startTime = performance.now();
    this.output = [];

    this.process.stdout?.on('data', (data) => {
      const output = data.toString();
      this.output.push(output);
      this.emit('stdout', output);
      if (this.options.logOutput) {
        console.log(`[SERVER STDOUT] ${output.trim()}`);
      }
    });

    this.process.stderr?.on('data', (data) => {
      const output = data.toString();
      this.output.push(output);
      this.emit('stderr', output);
      if (this.options.logOutput) {
        console.error(`[SERVER STDERR] ${output.trim()}`);
      }
    });

    this.process.on('exit', (code, signal) => {
      this.endTime = performance.now();
      this.emit('exit', code, signal);
    });

    this.process.on('error', (error) => {
      this.emit('error', error);
    });

    // Wait for server to start
    await this.waitForStartup();
  }

  /**
   * Stop the server with specified signal
   */
  async stop(signal: NodeJS['S']ignals = 'SIGINT'): Promise<number | null> {
    if (!this.process) {
      throw new Error('Server not started');
    }

    return new Promise((resolve) => {
      const timeout = this.options.timeout || 10000;

      const timeoutHandle = setTimeout(() => {
        if (this.process && !this.process.killed) {
          this.process.kill('SIGKILL');
        }
      }, timeout);

      this.process.once('exit', (code) => {
        clearTimeout(timeoutHandle);
        resolve(code);
      });

      this.process.kill(signal);
    });
  }

  /**
   * Force kill the server
   */
  kill(): void {
    if (this.process && !this.process.killed) {
      this.process.kill('SIGKILL');
    }
  }

  /**
   * Get server output
   */
  getOutput(): string[] {
    return [...this.output];
  }

  /**
   * Get server uptime
   */
  getUptime(): number {
    if (this.startTime === 0) return 0;
    return this.endTime === 0 ? performance.now() - this.startTime : this.endTime - this.startTime;
  }

  /**
   * Check if server is running
   */
  isRunning(): boolean {
    return this.process !== null && !this.process.killed && this.process.exitCode === null;
  }

  /**
   * Find the server executable
   */
  private findServerPath(): string | null {
    const possiblePaths = [
      './dist/index.js',
      './dist/src/index.js',
      './src/index.ts',
      './index.js',
    ];

    for (const serverPath of possiblePaths) {
      if (fs.existsSync(serverPath)) {
        return path.resolve(serverPath);
      }
    }

    return null;
  }

  /**
   * Get appropriate arguments for the server
   */
  private getArgsForServer(serverPath: string): string[] {
    if (serverPath.endsWith('.ts')) {
      return ['--loader', 'ts-node/esm'];
    }
    return [];
  }

  /**
   * Wait for server to start up
   */
  private async waitForStartup(): Promise<void> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Server startup timeout'));
      }, 10000);

      const checkStarted = () => {
        if (
          this.output.some(
            (line) =>
              line.includes('started') ||
              line.includes('listening') ||
              line.includes('ready') ||
              line.includes('Server running')
          )
        ) {
          clearTimeout(timeout);
          resolve();
          return;
        }

        if (this.process?.exitCode !== null) {
          clearTimeout(timeout);
          reject(new Error('Server failed to start'));
          return;
        }

        setTimeout(checkStarted, 100);
      };

      // Initial check after a short delay
      setTimeout(checkStarted, 500);
    });
  }

  /**
   * Cleanup server process
   */
  cleanup(): void {
    if (this.process && !this.process.killed) {
      this.process.kill('SIGKILL');
    }
    this.process = null;
    this.output = [];
    this.startTime = 0;
    this.endTime = 0;
  }
}

/**
 * Resource monitoring utility
 */
export class ResourceMonitor {
  private snapshots: ResourceSnapshot[] = [];

  /**
   * Take a resource snapshot
   */
  takeSnapshot(label?: string): ResourceSnapshot {
    const snapshot: ResourceSnapshot = {
      timestamp: performance.now(),
      memory: process.memoryUsage(),
      handles: process['_']getActiveHandles().length,
      requests: process['_']getActiveRequests().length,
      cpuUsage: process.cpuUsage(),
    };

    if (process.platform !== 'win32') {
      try {
        // On Unix systems, we can get open file descriptors
        const fdDir = '/proc/self/fd';
        if (fs.existsSync(fdDir)) {
          snapshot.openFiles = fs.readdirSync(fdDir);
        }
      } catch (error) {
        // Ignore errors accessing /proc
      }
    }

    this.snapshots.push(snapshot);
    return snapshot;
  }

  /**
   * Get all snapshots
   */
  getSnapshots(): ResourceSnapshot[] {
    return [...this.snapshots];
  }

  /**
   * Calculate difference between two snapshots
   */
  calculateDiff(
    before: ResourceSnapshot,
    after: ResourceSnapshot
  ): {
    memory: { heapUsed: number; heapTotal: number; external: number; rss: number };
    handles: number;
    requests: number;
  } {
    return {
      memory: {
        heapUsed: after.memory.heapUsed - before.memory.heapUsed,
        heapTotal: after.memory.heapTotal - before.memory.heapTotal,
        external: after.memory.external - before.memory.external,
        rss: after.memory.rss - before.memory.rss,
      },
      handles: after.handles - before.handles,
      requests: after.requests - before.requests,
    };
  }

  /**
   * Clear all snapshots
   */
  clear(): void {
    this.snapshots = [];
  }
}

/**
 * Shutdown test executor
 */
export class ShutdownTestExecutor {
  private resourceMonitor = new ResourceMonitor();

  /**
   * Execute a shutdown test
   */
  async executeTest(
    testName: string,
    testFn: (server: TestServerManager) => Promise<void>,
    options: TestServerOptions = {}
  ): Promise<ShutdownTestResult> {
    const result: ShutdownTestResult = {
      testName,
      passed: false,
      duration: 0,
      exitCode: null,
      signal: null,
      output: [],
      resources: {
        before: this.resourceMonitor.takeSnapshot('before-start'),
        after: {} as ResourceSnapshot,
        diff: {} as any,
      },
      errors: [],
      warnings: [],
    };

    const startTime = performance.now();

    try {
      const server = new TestServerManager({
        ...options,
        logOutput: options.logOutput || false,
      });

      // Take snapshot after server start
      server.on('stdout', (output) => {
        result.output.push(`[STDOUT] ${output.trim()}`);
      });

      server.on('stderr', (output) => {
        result.output.push(`[STDERR] ${output.trim()}`);
      });

      await server.start();
      this.resourceMonitor.takeSnapshot('after-start');

      // Execute the test function
      await testFn(server);

      // Wait for server to exit and get exit info
      const exitCode = await new Promise<number | null>((resolve) => {
        const timeout = setTimeout(() => {
          server.kill();
          resolve(null);
        }, 30000);

        server.once('exit', (code, signal) => {
          clearTimeout(timeout);
          result.exitCode = code;
          result.signal = signal;
          resolve(code);
        });
      });

      // Take final snapshot
      result.resources.after = this.resourceMonitor.takeSnapshot('after-shutdown');
      result.resources.diff = this.resourceMonitor.calculateDiff(
        result.resources.before,
        result.resources.after
      );

      // Evaluate test success
      result.passed = await this.evaluateTestSuccess(testName, exitCode, result);

      server.cleanup();
    } catch (error) {
      result.errors.push(error instanceof Error ? error.message : String(error));
      result.passed = false;
    }

    result.duration = performance.now() - startTime;
    return result;
  }

  /**
   * Evaluate if a test passed based on its characteristics
   */
  private async evaluateTestSuccess(
    testName: string,
    exitCode: number | null,
    result: ShutdownTestResult
  ): Promise<boolean> {
    // Basic success criteria
    if (exitCode === null) {
      result.warnings.push('Server did not exit cleanly');
      return false;
    }

    // Test-specific evaluation
    if (testName.includes('SIGINT') || testName.includes('SIGTERM')) {
      return (
        exitCode === 0 && this.outputContains(result.output, ['SIGINT', 'SIGTERM', 'shutdown'])
      );
    }

    if (testName.includes('graceful')) {
      return exitCode === 0 && !this.outputContains(result.output, ['error', 'failed']);
    }

    if (testName.includes('force')) {
      // Force shutdown may have non-zero exit code but should still exit
      return exitCode !== null;
    }

    if (testName.includes('memory') || testName.includes('resource')) {
      // Memory/resource tests should not have significant leaks
      const memoryDiff = result.resources.diff.memory.heapUsed;
      const handleDiff = result.resources.diff.handles;

      const memoryLeak = memoryDiff > 50 * 1024 * 1024; // 50MB threshold
      const handleLeak = handleDiff > 5; // 5 handles threshold

      if (memoryLeak) {
        result.warnings.push(`Potential memory leak: ${Math.round(memoryDiff / 1024 / 1024)}MB`);
      }

      if (handleLeak) {
        result.warnings.push(`Potential handle leak: ${handleDiff} handles`);
      }

      return !memoryLeak && !handleLeak && exitCode === 0;
    }

    // Default success criteria
    return exitCode === 0;
  }

  /**
   * Check if output contains specific keywords
   */
  private outputContains(output: string[], keywords: string[]): boolean {
    const outputText = output.join(' ').toLowerCase();
    return keywords.some((keyword) => outputText.includes(keyword.toLowerCase()));
  }

  /**
   * Clear resource monitor
   */
  clear(): void {
    this.resourceMonitor.clear();
  }
}

/**
 * Utility functions for shutdown testing
 */
export class ShutdownTestUtils {
  /**
   * Create test files for file handle testing
   */
  static async createTestFiles(count: number = 3): Promise<string[]> {
    const files: string[] = [];

    for (let i = 0; i < count; i++) {
      const filename = `./test-shutdown-${i}-${Date.now()}.tmp`;
      fs.writeFileSync(filename, `Test content ${i}\n`);
      files.push(filename);
    }

    return files;
  }

  /**
   * Cleanup test files
   */
  static async cleanupTestFiles(files: string[]): Promise<void> {
    for (const file of files) {
      try {
        fs.unlinkSync(file);
      } catch (error) {
        // File may already be deleted
      }
    }
  }

  /**
   * Create network load for testing
   */
  static async createNetworkLoad(concurrency: number = 5): Promise<void> {
    const promises = [];

    for (let i = 0; i < concurrency; i++) {
      promises.push(
        fetch('http://httpbin.org/delay/1', {
          signal: AbortSignal.timeout(5000),
        }).catch(() => {}) // Ignore errors
      );
    }

    await Promise.allSettled(promises);
  }

  /**
   * Generate test report
   */
  static generateReport(results: ShutdownTestResult[]): string {
    const totalTests = results.length;
    const passedTests = results.filter((r) => r.passed).length;
    const failedTests = totalTests - passedTests;

    const report = [
      '# MCP Server Shutdown Test Report',
      '='.repeat(50),
      '',
      `Generated: ${new Date().toISOString()}`,
      `Total Tests: ${totalTests}`,
      `Passed: ${passedTests}`,
      `Failed: ${failedTests}`,
      `Success Rate: ${Math.round((passedTests / totalTests) * 100)}%`,
      '',
      '## Test Results',
      '',
    ];

    results.forEach((result) => {
      const status = result.passed ? '✅ PASS' : '❌ FAIL';
      report.push(`${status} ${result.testName} (${Math.round(result.duration)}ms)`);

      if (result.exitCode !== null) {
        report.push(`   Exit Code: ${result.exitCode}`);
      }

      if (result.signal) {
        report.push(`   Signal: ${result.signal}`);
      }

      if (result.errors.length > 0) {
        report.push('   Errors:');
        result.errors.forEach((error) => report.push(`     - ${error}`));
      }

      if (result.warnings.length > 0) {
        report.push('   Warnings:');
        result.warnings.forEach((warning) => report.push(`     - ${warning}`));
      }

      report.push('');
    });

    return report.join('\n');
  }
}
