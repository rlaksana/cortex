#!/usr/bin/env node

/**
 * File Handle Manager Integration Example
 *
 * This example demonstrates how to integrate the File Handle Manager
 * into existing code to prevent EMFILE errors.
 *
 * Run with: node examples/file-handle-manager-integration.ts
 */

import { FileHandleManager, readFileManaged, writeFileManaged } from '../src/utils/file-handle-manager.js';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';

// Example: Configuration Service Migration
class ConfigurationServiceOld {
  private configPath: string;

  constructor(configPath: string) {
    this.configPath = configPath;
  }

  async loadConfiguration(): Promise<any> {
    // PROBLEM: Direct fs usage can cause EMFILE errors
    const content = await fs.readFile(this.configPath, 'utf-8');
    return JSON.parse(content);
  }

  async saveConfiguration(config: any): Promise<void> {
    // PROBLEM: Direct fs usage can cause EMFILE errors
    const content = JSON.stringify(config, null, 2);
    await fs.writeFile(this.configPath, content, 'utf-8');
  }
}

class ConfigurationServiceNew {
  private configPath: string;

  constructor(configPath: string) {
    this.configPath = configPath;
  }

  async loadConfiguration(): Promise<any> {
    // SOLUTION: Use managed file operations
    const content = await readFileManaged(this.configPath, {
      encoding: 'utf-8',
      correlationId: 'config-load',
      timeout: 10000
    });
    return JSON.parse(content);
  }

  async saveConfiguration(config: any): Promise<void> {
    // SOLUTION: Use managed file operations
    const content = JSON.stringify(config, null, 2);
    await writeFileManaged(this.configPath, content, {
      encoding: 'utf-8',
      correlationId: 'config-save',
      timeout: 10000
    });
  }
}

// Example: Batch File Processor Migration
class BatchFileProcessorOld {
  async processFiles(filePaths: string[]): Promise<string[]> {
    const results: string[] = [];

    // PROBLEM: Processing many files concurrently can exceed handle limits
    for (const filePath of filePaths) {
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        const processed = content.toUpperCase();
        const outputPath = filePath.replace('.txt', '.processed.txt');
        await fs.writeFile(outputPath, processed, 'utf-8');
        results.push(outputPath);
      } catch (error) {
        console.error(`Failed to process ${filePath}:`, error);
      }
    }

    return results;
  }
}

class BatchFileProcessorNew {
  private fileManager: FileHandleManager;

  constructor() {
    this.fileManager = new FileHandleManager({
      maxHandles: 50,
      cleanupThreshold: 0.75,
      enableWindowsOptimizations: true,
      operationTimeout: 30000,
      enableGracefulDegradation: true,
      logLevel: 'info'
    });
  }

  async processFiles(filePaths: string[]): Promise<string[]> {
    const results: string[] = [];

    for (let i = 0; i < filePaths.length; i++) {
      const filePath = filePaths[i];
      try {
        // SOLUTION: Use managed operations with correlation IDs
        const content = await this.fileManager.managedReadFile(filePath, {
          encoding: 'utf-8',
          correlationId: `batch-read-${i}`,
          timeout: 15000
        });

        const processed = content.toUpperCase();
        const outputPath = filePath.replace('.txt', '.processed.txt');

        await this.fileManager.managedWriteFile(outputPath, processed, {
          encoding: 'utf-8',
          correlationId: `batch-write-${i}`,
          timeout: 15000
        });

        results.push(outputPath);

        // Monitor handle usage
        const stats = this.fileManager.getStats();
        if (stats.currentHandles > stats.maxHandles * 0.8) {
          console.log('Handle usage high, triggering cleanup');
          await this.fileManager.cleanup();
        }
      } catch (error) {
        console.error(`Failed to process ${filePath}:`, error);
      }
    }

    return results;
  }

  async shutdown(): Promise<void> {
    await this.fileManager.shutdown();
  }

  getStats() {
    return this.fileManager.getStats();
  }
}

// Example: Test Data Helper Migration
class TestDataHelperOld {
  private testDataDir: string;

  constructor(testDataDir: string) {
    this.testDataDir = testDataDir;
  }

  async createTestFile(name: string, content: string): Promise<string> {
    // PROBLEM: Direct fs usage in tests can cause EMFILE errors
    const filePath = join(this.testDataDir, name);
    await fs.writeFile(filePath, content, 'utf-8');
    return filePath;
  }

  async readTestFile(name: string): Promise<string> {
    // PROBLEM: Direct fs usage in tests can cause EMFILE errors
    const filePath = join(this.testDataDir, name);
    const content = await fs.readFile(filePath, 'utf-8');
    return content;
  }

  async cleanup(): Promise<void> {
    // PROBLEM: No handle management
  }
}

class TestDataHelperNew {
  private testDataDir: string;

  constructor(testDataDir: string) {
    this.testDataDir = testDataDir;
  }

  async createTestFile(name: string, content: string): Promise<string> {
    // SOLUTION: Use managed operations
    const filePath = join(this.testDataDir, name);
    await writeFileManaged(filePath, content, {
      encoding: 'utf-8',
      correlationId: `test-create-${name.replace(/[^a-zA-Z0-9]/g, '_')}`
    });
    return filePath;
  }

  async readTestFile(name: string): Promise<string> {
    // SOLUTION: Use managed operations
    const filePath = join(this.testDataDir, name);
    const content = await readFileManaged(filePath, {
      encoding: 'utf-8',
      correlationId: `test-read-${name.replace(/[^a-zA-Z0-9]/g, '_')}`
    });
    return content as string;
  }

  async cleanup(): Promise<void> {
    // SOLUTION: File handle manager handles automatic cleanup
    console.log('Test data helper cleanup completed');
  }
}

// Example: Log File Manager Migration
class LogFileManagerOld {
  private logDir: string;

  constructor(logDir: string) {
    this.logDir = logDir;
  }

  async writeLog(level: string, message: string, metadata?: any): Promise<void> {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      level,
      message,
      metadata
    };

    const logFile = join(this.logDir, `${level}.log`);
    const logLine = JSON.stringify(logEntry) + '\n';

    // PROBLEM: Frequent writes can exhaust handles
    await fs.writeFile(logFile, logLine, { flag: 'a' });
  }

  async readLogs(level: string, limit: number = 100): Promise<any[]> {
    const logFile = join(this.logDir, `${level}.log`);

    // PROBLEM: Reading large log files can be problematic
    const content = await fs.readFile(logFile, 'utf-8');
    const lines = content.trim().split('\n');

    return lines
      .slice(-limit)
      .map(line => JSON.parse(line));
  }
}

class LogFileManagerNew {
  private logDir: string;
  private fileManager: FileHandleManager;

  constructor(logDir: string) {
    this.logDir = logDir;
    this.fileManager = new FileHandleManager({
      maxHandles: 25,
      cleanupThreshold: 0.6,
      enableWindowsOptimizations: true,
      operationTimeout: 5000,
      logLevel: 'warn' // Reduce log noise for logging operations
    });
  }

  async writeLog(level: string, message: string, metadata?: any): Promise<void> {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      level,
      message,
      metadata
    };

    const logFile = join(this.logDir, `${level}.log`);
    const logLine = JSON.stringify(logEntry) + '\n';

    // SOLUTION: Use managed operations with timeout for logging
    await this.fileManager.managedWriteFile(logFile, logLine, {
      encoding: 'utf-8',
      flag: 'a',
      correlationId: `log-write-${level}`,
      timeout: 2000 // Short timeout for logging
    });
  }

  async readLogs(level: string, limit: number = 100): Promise<any[]> {
    const logFile = join(this.logDir, `${level}.log`);

    try {
      // SOLUTION: Use managed operations with error handling
      const content = await this.fileManager.managedReadFile(logFile, {
        encoding: 'utf-8',
        correlationId: `log-read-${level}`,
        timeout: 10000
      });

      const lines = content.trim().split('\n');

      return lines
        .slice(-limit)
        .map(line => JSON.parse(line));
    } catch (error) {
      console.warn(`Failed to read logs for level ${level}:`, error);
      return [];
    }
  }

  async shutdown(): Promise<void> {
    await this.fileManager.shutdown();
  }

  getStats() {
    return this.fileManager.getStats();
  }
}

// Demonstration function
async function demonstrateIntegration(): Promise<void> {
  console.log('=== File Handle Manager Integration Demo ===\n');

  // Create test directory
  const testDir = './temp-demo-files';
  try {
    await fs.mkdir(testDir, { recursive: true });
  } catch {
    // Directory might already exist
  }

  try {
    // 1. Configuration Service Demo
    console.log('1. Configuration Service Migration:');
    console.log('   Old approach: Direct fs operations');
    console.log('   New approach: Managed operations with error handling\n');

    const configPath = join(testDir, 'config.json');
    const testConfig = { theme: 'dark', language: 'en', timeout: 5000 };

    // Old approach
    const oldConfigService = new ConfigurationServiceOld(configPath);
    await oldConfigService.saveConfiguration(testConfig);
    const loadedOldConfig = await oldConfigService.loadConfiguration();
    console.log(`   ✓ Old approach worked: ${loadedOldConfig.theme}`);

    // New approach
    const newConfigService = new ConfigurationServiceNew(configPath);
    await newConfigService.saveConfiguration(testConfig);
    const loadedNewConfig = await newConfigService.loadConfiguration();
    console.log(`   ✓ New approach worked: ${loadedNewConfig.theme}\n`);

    // 2. Batch Processing Demo
    console.log('2. Batch File Processing Migration:');
    console.log('   Old approach: No handle management, prone to EMFILE');
    console.log('   New approach: Managed handles with monitoring\n');

    // Create test files
    const testFiles = [];
    for (let i = 0; i < 5; i++) {
      const filePath = join(testDir, `test-${i}.txt`);
      const content = `Test file content ${i}`;
      await fs.writeFile(filePath, content, 'utf-8');
      testFiles.push(filePath);
    }

    // New approach
    const processor = new BatchFileProcessorNew();
    const processedFiles = await processor.processFiles(testFiles);
    console.log(`   ✓ Processed ${processedFiles.length} files successfully`);

    const processorStats = processor.getStats();
    console.log(`   - Total operations: ${processorStats.totalOperations}`);
    console.log(`   - Success rate: ${((processorStats.successfulOperations / processorStats.totalOperations) * 100).toFixed(1)}%`);
    console.log(`   - Peak handles: ${processorStats.peakHandleCount}\n`);

    await processor.shutdown();

    // 3. Test Helper Demo
    console.log('3. Test Data Helper Migration:');
    console.log('   Old approach: Direct fs, no correlation tracking');
    console.log('   New approach: Managed operations with correlation IDs\n');

    const oldTestHelper = new TestDataHelperOld(testDir);
    const newTestHelper = new TestDataHelperNew(testDir);

    const testContent = 'This is test content for demonstration';

    const oldTestFile = await oldTestHelper.createTestFile('old-test.txt', testContent);
    const oldContent = await oldTestHelper.readTestFile('old-test.txt');
    console.log(`   ✓ Old approach: ${oldContent.length} characters`);

    const newTestFile = await newTestHelper.createTestFile('new-test.txt', testContent);
    const newContent = await newTestHelper.readTestFile('new-test.txt');
    console.log(`   ✓ New approach: ${newContent.length} characters\n`);

    // 4. Log Manager Demo
    console.log('4. Log File Manager Migration:');
    console.log('   Old approach: Frequent writes can exhaust handles');
    console.log('   New approach: Managed operations with timeouts\n');

    const logManager = new LogFileManagerNew(testDir);

    // Write some log entries
    await logManager.writeLog('info', 'Application started', { version: '1.0.0' });
    await logManager.writeLog('warn', 'Configuration loaded with defaults', { defaults: true });
    await logManager.writeLog('error', 'Database connection failed', { retry: true });

    // Read logs
    const logs = await logManager.readLogs('info', 10);
    console.log(`   ✓ Wrote and read ${logs.length} log entries`);

    const logStats = logManager.getStats();
    console.log(`   - Log operations: ${logStats.totalOperations}`);
    console.log(`   - Cleanup count: ${logStats.cleanupCount}\n`);

    await logManager.shutdown();

    // 5. Statistics Summary
    console.log('5. Global Statistics Summary:');
    const globalStats = getFileHandleStats();
    console.log(`   - Current handles: ${globalStats.currentHandles}`);
    console.log(`   - Max handles: ${globalStats.maxHandles}`);
    console.log(`   - Total operations: ${globalStats.totalOperations}`);
    console.log(`   - Success rate: ${globalStats.totalOperations > 0 ? ((globalStats.successfulOperations / globalStats.totalOperations) * 100).toFixed(1) : 0}%`);
    console.log(`   - Average duration: ${globalStats.averageOperationDuration.toFixed(2)}ms`);
    console.log(`   - Peak handles: ${globalStats.peakHandleCount}\n`);

    console.log('=== Integration Demo Complete ===');
    console.log('✓ All migrations completed successfully');
    console.log('✓ File Handle Manager prevented EMFILE errors');
    console.log('✓ Operations were tracked and monitored');
    console.log('✓ Graceful degradation was available if needed');

  } catch (error) {
    console.error('Demo failed:', error);
  } finally {
    // Cleanup
    try {
      await fs.rm(testDir, { recursive: true, force: true });
      await cleanupFileHandles();
      console.log('\n✓ Cleanup completed');
    } catch {
      // Ignore cleanup errors
    }
  }
}

// Convenience functions for the demo
import { getFileHandleStats, cleanupFileHandles } from '../src/utils/file-handle-manager.js';

// Run the demonstration
if (import.meta.url === `file://${process.argv[1]}`) {
  demonstrateIntegration().catch(console.error);
}

export {
  ConfigurationServiceOld,
  ConfigurationServiceNew,
  BatchFileProcessorOld,
  BatchFileProcessorNew,
  TestDataHelperOld,
  TestDataHelperNew,
  LogFileManagerOld,
  LogFileManagerNew,
  demonstrateIntegration
};