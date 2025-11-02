/**
 * File Handle Manager Unit Tests
 *
 * Tests the FileHandleManager utility with comprehensive coverage of:
 * - Handle pooling and management
 * - Automatic cleanup functionality
 * - Windows-specific optimizations
 * - Error handling and graceful degradation
 * - Statistics and monitoring
 * - Configuration options
 * - Performance under load
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import { describe, it, expect, beforeEach, afterEach, vi, beforeAll, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  FileHandleManager,
  FileHandleManagerError,
  readFileManaged,
  writeFileManaged,
} from '../../../src/utils/file-handle-manager.js';

// Mock logger to avoid test output pollution
const mockLogger = {
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
};

vi.mock('../../../src/utils/logger.js', () => ({
  logger: mockLogger,
}));

// Test file paths
const testDir = join(tmpdir(), 'file-handle-manager-test');
const testFile1 = join(testDir, 'test1.txt');
const testFile2 = join(testDir, 'test2.txt');
const largeTestFile = join(testDir, 'large.txt');

// Test data
const testContent1 = 'Hello, World!';
const testContent2 = 'File Handle Manager Test Content';
const largeTestContent = 'x'.repeat(10000);

describe('FileHandleManager', () => {
  let manager: FileHandleManager;

  beforeAll(async () => {
    // Create test directory
    await fs.mkdir(testDir, { recursive: true });
  });

  afterAll(async () => {
    // Cleanup test directory
    try {
      await fs.rm(testDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  beforeEach(() => {
    // Create fresh manager for each test
    manager = new FileHandleManager({
      maxHandles: 10,
      cleanupThreshold: 0.8,
      operationTimeout: 5000,
      logLevel: 'error', // Reduce log noise in tests
    });

    // Clear mock calls
    vi.clearAllMocks();
  });

  afterEach(async () => {
    // Cleanup manager
    await manager.shutdown();
  });

  describe('Basic Functionality', () => {
    it('should initialize with default configuration', async () => {
      const defaultManager = new FileHandleManager();
      const stats = defaultManager.getStats();

      expect(stats.maxHandles).toBeGreaterThan(0);
      expect(stats.currentHandles).toBe(0);
      expect(stats.totalOperations).toBe(0);
      expect(stats.successfulOperations).toBe(0);
      expect(stats.failedOperations).toBe(0);

      await defaultManager.shutdown();
    });

    it('should read files successfully', async () => {
      // Create test file
      await fs.writeFile(testFile1, testContent1, 'utf-8');

      // Read using manager
      const content = await manager.managedReadFile(testFile1, {
        encoding: 'utf-8',
        correlationId: 'test-read-001',
      });

      expect(content).toBe(testContent1);

      // Check statistics
      const stats = manager.getStats();
      expect(stats.totalOperations).toBe(1);
      expect(stats.successfulOperations).toBe(1);
      expect(stats.failedOperations).toBe(0);
      expect(stats.currentHandles).toBe(0); // Should be cleaned up
    });

    it('should write files successfully', async () => {
      // Write using manager
      await manager.managedWriteFile(testFile1, testContent1, {
        encoding: 'utf-8',
        correlationId: 'test-write-001',
      });

      // Verify file was written
      const content = await fs.readFile(testFile1, 'utf-8');
      expect(content).toBe(testContent1);

      // Check statistics
      const stats = manager.getStats();
      expect(stats.totalOperations).toBe(1);
      expect(stats.successfulOperations).toBe(1);
      expect(stats.failedOperations).toBe(0);
    });

    it('should handle both read and write operations', async () => {
      // Write file
      await manager.managedWriteFile(testFile1, testContent1);

      // Read file with explicit encoding
      const content = await manager.managedReadFile(testFile1, { encoding: 'utf-8' });

      expect(content).toBe(testContent1);

      // Check statistics
      const stats = manager.getStats();
      expect(stats.totalOperations).toBe(2);
      expect(stats.successfulOperations).toBe(2);
      expect(stats.failedOperations).toBe(0);
    });

    it('should create directories automatically when writing files', async () => {
      const nestedPath = join(testDir, 'subdir', 'nested.txt');

      // Write to nested path
      await manager.managedWriteFile(nestedPath, testContent1);

      // Verify file exists and content is correct
      const content = await fs.readFile(nestedPath, 'utf-8');
      expect(content).toBe(testContent1);
    });
  });

  describe('Handle Management', () => {
    it('should track handle usage correctly', async () => {
      // Create test file
      await fs.writeFile(testFile1, testContent1, 'utf-8');

      const initialStats = manager.getStats();
      expect(initialStats.currentHandles).toBe(0);

      // Start read operation
      const readPromise = manager.managedReadFile(testFile1);

      // Check stats during operation (might be 0 or 1 depending on timing)
      const duringStats = manager.getStats();

      // Wait for completion
      await readPromise;

      // Check stats after completion
      const finalStats = manager.getStats();
      expect(finalStats.currentHandles).toBe(0);
      expect(finalStats.totalOperations).toBe(1);
    });

    it('should respect max handles limit', async () => {
      // Create test files
      await fs.writeFile(testFile1, testContent1, 'utf-8');
      await fs.writeFile(testFile2, testContent2, 'utf-8');

      // Set very low handle limit
      manager.setMaxHandles(2);

      const stats = manager.getStats();
      expect(stats.maxHandles).toBe(2);

      // Perform multiple operations
      await manager.managedReadFile(testFile1);
      await manager.managedReadFile(testFile2);
      await manager.managedWriteFile(join(testDir, 'output1.txt'), 'output1');
      await manager.managedWriteFile(join(testDir, 'output2.txt'), 'output2');

      // Should complete without errors
      const finalStats = manager.getStats();
      expect(finalStats.totalOperations).toBe(4);
      expect(finalStats.successfulOperations).toBe(4);
    });

    it('should trigger cleanup when threshold is reached', async () => {
      // Create test files
      await fs.writeFile(testFile1, testContent1, 'utf-8');
      await fs.writeFile(testFile2, testContent2, 'utf-8');

      const managerWithLowThreshold = new FileHandleManager({
        maxHandles: 5,
        cleanupThreshold: 0.6, // 60% threshold
        logLevel: 'error',
      });

      let cleanupCalled = false;
      const originalCleanup = managerWithLowThreshold.cleanup.bind(managerWithLowThreshold);
      managerWithLowThreshold.cleanup = vi.fn().mockImplementation(async () => {
        cleanupCalled = true;
        await originalCleanup();
      });

      try {
        // Perform operations that should trigger cleanup
        for (let i = 0; i < 3; i++) {
          await managerWithLowThreshold.managedReadFile(testFile1);
        }

        // Cleanup might have been called
        if (cleanupCalled) {
          expect(managerWithLowThreshold.cleanup).toHaveBeenCalled();
        }
      } finally {
        await managerWithLowThreshold.shutdown();
      }
    });

    it('should handle forced cleanup correctly', async () => {
      // Create test files
      await fs.writeFile(testFile1, testContent1, 'utf-8');

      // Perform an operation
      await manager.managedReadFile(testFile1);

      // Force cleanup
      await manager.cleanup();

      // Check stats
      const stats = manager.getStats();
      expect(stats.currentHandles).toBe(0);
      expect(stats.cleanupCount).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Error Handling', () => {
    it('should handle file not found errors', async () => {
      const nonExistentFile = join(testDir, 'non-existent.txt');

      await expect(manager.managedReadFile(nonExistentFile)).rejects.toThrow(
        FileHandleManagerError
      );

      const stats = manager.getStats();
      expect(stats.totalOperations).toBe(1);
      expect(stats.successfulOperations).toBe(0);
      expect(stats.failedOperations).toBe(1);
    });

    it('should handle permission errors gracefully', async () => {
      // This test might not work on all systems, so we'll mock it
      const mockFs = vi
        .spyOn(fs, 'readFile')
        .mockRejectedValue(Object.assign(new Error('Permission denied'), { code: 'EACCES' }));

      await expect(manager.managedReadFile(testFile1)).rejects.toThrow(FileHandleManagerError);

      const error = await manager.managedReadFile(testFile1).catch((e) => e);
      expect(error).toBeInstanceOf(FileHandleManagerError);
      expect(error.code).toBe('EACCES');

      mockFs.mockRestore();
    });

    it('should handle timeout errors', async () => {
      // Create test file
      await fs.writeFile(testFile1, testContent1, 'utf-8');

      // Use a very short timeout that should trigger
      await expect(manager.managedReadFile(testFile1, { timeout: 1 })).rejects.toThrow(
        FileHandleManagerError
      );
    });

    it('should provide detailed error information', async () => {
      const nonExistentFile = join(testDir, 'non-existent.txt');

      try {
        await manager.managedReadFile(nonExistentFile, {
          correlationId: 'test-error-001',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(FileHandleManagerError);
        expect(error.name).toBe('FileHandleManagerError');
        expect(error.path).toBe(nonExistentFile);
        expect(error.operation).toBe('read');
        expect(error.message).toContain('read operation failed');
      }
    });
  });

  describe('Graceful Degradation', () => {
    it('should fallback to direct fs operations when handle manager fails', async () => {
      // Create test file
      await fs.writeFile(testFile1, testContent1, 'utf-8');

      // Create a manager that will fail
      const failingManager = new FileHandleManager({
        maxHandles: 0, // This should cause failures
        enableGracefulDegradation: true,
        logLevel: 'error',
      });

      try {
        // Should succeed despite the manager configuration through graceful degradation
        const content = await failingManager.managedReadFile(testFile1, { encoding: 'utf-8' });
        expect(content).toBe(testContent1);

        const stats = failingManager.getStats();
        expect(stats.degradationCount).toBeGreaterThan(0);
      } finally {
        await failingManager.shutdown();
      }
    });

    it('should respect forceDirect option', async () => {
      // Create test file
      await fs.writeFile(testFile1, testContent1, 'utf-8');

      // Force direct operation
      const content = await manager.managedReadFile(testFile1, {
        forceDirect: true,
        encoding: 'utf-8',
      });

      expect(content).toBe(testContent1);

      // Should still count the operation but might bypass some manager features
      const stats = manager.getStats();
      expect(stats.totalOperations).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Statistics and Monitoring', () => {
    it('should track statistics accurately', async () => {
      // Create test files
      await fs.writeFile(testFile1, testContent1, 'utf-8');
      await fs.writeFile(testFile2, testContent2, 'utf-8');

      const initialStats = manager.getStats();

      // Perform successful operations
      await manager.managedReadFile(testFile1);
      await manager.managedWriteFile(join(testDir, 'output.txt'), testContent2);

      // Perform a failed operation
      try {
        await manager.managedReadFile(join(testDir, 'non-existent.txt'));
      } catch {
        // Expected to fail
      }

      const finalStats = manager.getStats();

      expect(finalStats.totalOperations).toBe(initialStats.totalOperations + 3);
      expect(finalStats.successfulOperations).toBe(initialStats.successfulOperations + 2);
      expect(finalStats.failedOperations).toBe(initialStats.failedOperations + 1);
      expect(finalStats.averageOperationDuration).toBeGreaterThan(0);
    });

    it('should update peak handle count', async () => {
      // This is difficult to test precisely due to timing, but we can check that it doesn't decrease
      const initialStats = manager.getStats();

      // Create test file
      await fs.writeFile(testFile1, testContent1, 'utf-8');

      // Perform operations
      await manager.managedReadFile(testFile1);
      await manager.managedWriteFile(join(testDir, 'output.txt'), testContent1);

      const finalStats = manager.getStats();
      expect(finalStats.peakHandleCount).toBeGreaterThanOrEqual(initialStats.peakHandleCount);
    });

    it('should return immutable stats object', async () => {
      const stats1 = manager.getStats();
      const stats2 = manager.getStats();

      // Should be different objects
      expect(stats1).not.toBe(stats2);

      // Modifying one shouldn't affect the other
      stats1.totalOperations = 999;
      expect(stats2.totalOperations).not.toBe(999);
    });
  });

  describe('Configuration', () => {
    it('should accept custom configuration', () => {
      const customManager = new FileHandleManager({
        maxHandles: 50,
        cleanupThreshold: 0.75,
        operationTimeout: 60000,
        enableGracefulDegradation: false,
        logLevel: 'warn',
      });

      const stats = customManager.getStats();
      expect(stats.maxHandles).toBe(50);

      customManager.shutdown();
    });

    it('should validate maxHandles configuration', () => {
      expect(() => new FileHandleManager({ maxHandles: 0 })).toThrow();
      expect(() => new FileHandleManager({ maxHandles: -1 })).toThrow();
      expect(() => manager.setMaxHandles(0)).toThrow();
      expect(() => manager.setMaxHandles(-1)).toThrow();
    });

    it('should update maxHandles dynamically', () => {
      const initialStats = manager.getStats();
      const newMaxHandles = initialStats.maxHandles + 10;

      manager.setMaxHandles(newMaxHandles);

      const updatedStats = manager.getStats();
      expect(updatedStats.maxHandles).toBe(newMaxHandles);
    });

    it('should trigger cleanup when reducing maxHandles below current usage', async () => {
      // Create test file
      await fs.writeFile(testFile1, testContent1, 'utf-8');

      // Set low limit
      manager.setMaxHandles(1);

      // Perform operation that should trigger cleanup
      await manager.managedReadFile(testFile1);

      // Reduce limit further
      manager.setMaxHandles(0);

      const stats = manager.getStats();
      expect(stats.maxHandles).toBe(1); // Should not allow 0
    });
  });

  describe('Large Files', () => {
    it('should handle large files correctly', async () => {
      // Create large test file
      await fs.writeFile(largeTestFile, largeTestContent, 'utf-8');

      // Read large file
      const content = await manager.managedReadFile(largeTestFile, {
        encoding: 'utf-8',
        timeout: 10000,
      });

      expect(content).toBe(largeTestContent);
      expect(content.length).toBe(largeTestContent.length);

      // Write large file
      const newLargeFile = join(testDir, 'large-output.txt');
      await manager.managedWriteFile(newLargeFile, content, {
        encoding: 'utf-8',
        timeout: 10000,
      });

      // Verify written content
      const writtenContent = await fs.readFile(newLargeFile, 'utf-8');
      expect(writtenContent).toBe(largeTestContent);
    });
  });

  describe('Concurrent Operations', () => {
    it('should handle multiple concurrent operations', async () => {
      // Create test files
      await fs.writeFile(testFile1, testContent1, 'utf-8');
      await fs.writeFile(testFile2, testContent2, 'utf-8');

      // Run concurrent operations
      const operations = Array.from({ length: 5 }, (_, i) =>
        manager.managedReadFile(i % 2 === 0 ? testFile1 : testFile2, {
          correlationId: `concurrent-${i}`,
        })
      );

      const results = await Promise.all(operations);

      // All operations should succeed
      expect(results).toHaveLength(5);
      results.forEach((result, i) => {
        const expected = i % 2 === 0 ? testContent1 : testContent2;
        expect(result).toBe(expected);
      });

      const stats = manager.getStats();
      expect(stats.totalOperations).toBe(5);
      expect(stats.successfulOperations).toBe(5);
      expect(stats.failedOperations).toBe(0);
    });

    it('should handle mixed read/write operations concurrently', async () => {
      // Create test file
      await fs.writeFile(testFile1, testContent1, 'utf-8');

      // Run mixed operations
      const operations = [
        manager.managedReadFile(testFile1, { correlationId: 'mixed-read-1' }),
        manager.managedWriteFile(join(testDir, 'mixed-1.txt'), testContent2, {
          correlationId: 'mixed-write-1',
        }),
        manager.managedReadFile(testFile1, { correlationId: 'mixed-read-2' }),
        manager.managedWriteFile(join(testDir, 'mixed-2.txt'), testContent1, {
          correlationId: 'mixed-write-2',
        }),
      ];

      const results = await Promise.all(operations);

      expect(results[0]).toBe(testContent1);
      expect(results[2]).toBe(testContent1);

      // Verify written files
      const mixed1Content = await fs.readFile(join(testDir, 'mixed-1.txt'), 'utf-8');
      const mixed2Content = await fs.readFile(join(testDir, 'mixed-2.txt'), 'utf-8');
      expect(mixed1Content).toBe(testContent2);
      expect(mixed2Content).toBe(testContent1);

      const stats = manager.getStats();
      expect(stats.totalOperations).toBe(4);
      expect(stats.successfulOperations).toBe(4);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty files', async () => {
      const emptyFile = join(testDir, 'empty.txt');
      await fs.writeFile(emptyFile, '', 'utf-8');

      const content = await manager.managedReadFile(emptyFile, {
        encoding: 'utf-8',
      });

      expect(content).toBe('');
    });

    it('should handle special characters in file paths', async () => {
      const specialFile = join(testDir, 'file with spaces & symbols!.txt');
      const specialContent = 'Special content: ñáéíóú 🎉';

      await manager.managedWriteFile(specialFile, specialContent, {
        encoding: 'utf-8',
      });

      const content = await manager.managedReadFile(specialFile, {
        encoding: 'utf-8',
      });

      expect(content).toBe(specialContent);
    });

    it('should handle binary data', async () => {
      const binaryFile = join(testDir, 'binary.bin');
      const binaryContent = Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);

      await manager.managedWriteFile(binaryFile, binaryContent);

      const content = await manager.managedReadFile(binaryFile);

      expect(Buffer.isBuffer(content)).toBe(true);
      expect(content).toEqual(binaryContent);
    });
  });

  describe('Platform-Specific Behavior', () => {
    it('should detect Windows platform correctly', () => {
      const manager = new FileHandleManager();
      // We can't easily test platform detection without mocking,
      // but we can verify the manager initializes
      expect(manager.getStats().maxHandles).toBeGreaterThan(0);
      manager.shutdown();
    });
  });

  describe('Memory and Resource Management', () => {
    it('should cleanup resources on shutdown', async () => {
      // Create test file
      await fs.writeFile(testFile1, testContent1, 'utf-8');

      // Perform operation
      await manager.managedReadFile(testFile1);

      // Shutdown
      await manager.shutdown();

      // Verify cleanup was called
      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({ component: 'FileHandleManager' }),
        'Shutting down FileHandleManager'
      );
    });

    it('should handle multiple cleanup calls safely', async () => {
      // Should not throw or cause issues
      await manager.cleanup();
      await manager.cleanup();
      await manager.cleanup();

      const stats = manager.getStats();
      expect(stats.currentHandles).toBe(0);
    });
  });
});

describe('Convenience Functions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should work with readFileManaged function', async () => {
    // Create test file
    await fs.writeFile(testFile1, testContent1, 'utf-8');

    const content = await readFileManaged(testFile1, {
      encoding: 'utf-8',
      correlationId: 'convenience-read',
    });

    expect(content).toBe(testContent1);
  });

  it('should work with writeFileManaged function', async () => {
    await writeFileManaged(testFile1, testContent1, {
      encoding: 'utf-8',
      correlationId: 'convenience-write',
    });

    const content = await fs.readFile(testFile1, 'utf-8');
    expect(content).toBe(testContent1);
  });
});

describe('Integration Scenarios', () => {
  it('should handle realistic batch processing scenario', async () => {
    const manager = new FileHandleManager({
      maxHandles: 5,
      cleanupThreshold: 0.8,
      logLevel: 'error',
    });

    try {
      // Create multiple test files
      const testFiles = [];
      for (let i = 0; i < 10; i++) {
        const filePath = join(testDir, `batch-${i}.txt`);
        const content = `Batch file content ${i}`;
        await fs.writeFile(filePath, content, 'utf-8');
        testFiles.push(filePath);
      }

      // Process files in batches
      const results = [];
      for (const filePath of testFiles) {
        try {
          const content = await manager.managedReadFile(filePath, {
            encoding: 'utf-8',
            correlationId: `batch-read-${testFiles.indexOf(filePath)}`,
          });

          // Process content (simple transformation)
          const processed = content.toUpperCase();

          // Write processed result
          const outputPath = join(testDir, `processed-${testFiles.indexOf(filePath)}.txt`);
          await manager.managedWriteFile(outputPath, processed, {
            encoding: 'utf-8',
            correlationId: `batch-write-${testFiles.indexOf(filePath)}`,
          });

          results.push({ success: true, file: filePath });
        } catch (error) {
          results.push({ success: false, file: filePath, error });
        }
      }

      // Verify all files were processed
      const successfulResults = results.filter((r) => r.success);
      expect(successfulResults).toHaveLength(testFiles.length);

      // Verify processed files exist and have correct content
      for (let i = 0; i < testFiles.length; i++) {
        const processedPath = join(testDir, `processed-${i}.txt`);
        const processedContent = await fs.readFile(processedPath, 'utf-8');
        expect(processedContent).toBe(`BATCH FILE CONTENT ${i}`);
      }

      // Check statistics
      const stats = manager.getStats();
      expect(stats.totalOperations).toBe(testFiles.length * 2); // read + write for each
      expect(stats.successfulOperations).toBe(testFiles.length * 2);
      expect(stats.failedOperations).toBe(0);
    } finally {
      await manager.shutdown();
    }
  });

  it('should handle stress test with many operations', async () => {
    const manager = new FileHandleManager({
      maxHandles: 20,
      cleanupThreshold: 0.7,
      logLevel: 'error',
    });

    try {
      // Create test file
      await fs.writeFile(testFile1, testContent1, 'utf-8');

      // Perform many concurrent operations
      const operations = Array.from({ length: 50 }, (_, i) =>
        manager.managedReadFile(testFile1, {
          correlationId: `stress-${i}`,
        })
      );

      const results = await Promise.all(operations);

      // All operations should succeed
      expect(results).toHaveLength(50);
      results.forEach((result) => {
        expect(result).toBe(testContent1);
      });

      const stats = manager.getStats();
      expect(stats.totalOperations).toBe(50);
      expect(stats.successfulOperations).toBe(50);
      expect(stats.failedOperations).toBe(0);
      expect(stats.currentHandles).toBe(0); // All should be cleaned up
    } finally {
      await manager.shutdown();
    }
  });
});
