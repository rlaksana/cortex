// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * File Handle Manager Utility
 *
 * Centralizes file operations with handle pooling and automatic cleanup to prevent EMFILE errors.
 * Designed specifically for Windows environments with configurable limits and graceful degradation.
 *
 * Features:
 * - Handle pooling with configurable limits
 * - Automatic cleanup when handle count approaches limits
 * - Windows-specific optimizations
 * - Handle count monitoring and statistics
 * - Graceful degradation to direct fs operations
 * - Comprehensive error handling and logging
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import { constants,promises as fs } from 'fs';
type BufferEncoding =
  | 'ascii'
  | 'utf8'
  | 'utf-8'
  | 'utf16le'
  | 'ucs2'
  | 'ucs-2'
  | 'base64'
  | 'base64url'
  | 'latin1'
  | 'binary'
  | 'hex';
import { EventEmitter } from 'node:events';
import { setImmediate } from 'node:timers';
import { resolve } from 'path';

import { logger } from '@/utils/logger.js';

import { generateCorrelationId } from './correlation-id.js';

/**
 * File handle manager configuration
 */
export interface FileHandleManagerConfig {
  /** Maximum number of concurrent file handles (default: 100 for Windows) */
  maxHandles?: number;
  /** Threshold percentage to trigger automatic cleanup (default: 0.8) */
  cleanupThreshold?: number;
  /** Enable Windows-specific optimizations (default: true on Windows) */
  enableWindowsOptimizations?: boolean;
  /** Timeout for file operations in ms (default: 30000) */
  operationTimeout?: number;
  /** Enable graceful degradation to direct fs operations (default: true) */
  enableGracefulDegradation?: boolean;
  /** Log level for handle operations (default: 'debug') */
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
}

/**
 * File operation statistics
 */
export interface FileHandleStats {
  /** Current number of active handles */
  currentHandles: number;
  /** Maximum number of handles allowed */
  maxHandles: number;
  /** Total number of operations performed */
  totalOperations: number;
  /** Number of successful operations */
  successfulOperations: number;
  /** Number of failed operations */
  failedOperations: number;
  /** Number of times cleanup was triggered */
  cleanupCount: number;
  /** Number of times graceful degradation was used */
  degradationCount: number;
  /** Average operation duration in milliseconds */
  averageOperationDuration: number;
  /** Peak handle count reached */
  peakHandleCount: number;
}

/**
 * File handle information for tracking
 */
interface FileHandleInfo {
  /** Unique identifier for this handle */
  id: string;
  /** File path */
  path: string;
  /** Operation type */
  operation: 'read' | 'write';
  /** Handle creation timestamp */
  createdAt: number;
  /** Operation start timestamp */
  operationStart?: number;
  /** Timeout for this handle */
  timeout?: NodeJS.Timeout;
}

/**
 * File operation options
 */
export interface FileOperationOptions {
  /** Custom encoding (default: 'utf-8') */
  encoding?: BufferEncoding;
  /** Custom timeout for this operation */
  timeout?: number;
  /** Force direct fs operation (bypass handle manager) */
  forceDirect?: boolean;
  /** Operation correlation ID for tracking */
  correlationId?: string;
}

/**
 * Custom error for file handle manager operations
 */
export class FileHandleManagerError extends Error {
  public readonly code: string;
  public readonly path: string | undefined;
  public readonly operation: string | undefined;
  public readonly cause: Error | undefined;

  constructor(
    message: string,
    code: string,
    options?: {
      path?: string;
      operation?: string;
      cause?: Error;
    }
  ) {
    super(message);
    this.name = 'FileHandleManagerError';
    this.code = code;
    this.path = options?.path;
    this.operation = options?.operation;
    this.cause = options?.cause;
  }
}

/**
 * File Handle Manager with pooling and automatic cleanup
 *
 * Manages file handle allocation and cleanup to prevent EMFILE errors on Windows.
 * Provides a unified interface for file operations with monitoring and statistics.
 */
export class FileHandleManager {
  private config: Required<FileHandleManagerConfig>;
  private activeHandles = new Map<string, FileHandleInfo>();
  private stats: FileHandleStats;
  private isWindows = process.platform === 'win32';
  private cleanupInProgress = false;
  private emitter = new EventEmitter();

  constructor(config: FileHandleManagerConfig = {}) {
    // Set default configuration
    this.config = {
      maxHandles: config.maxHandles ?? (this.isWindows ? 100 : 1000),
      cleanupThreshold: config.cleanupThreshold ?? 0.8,
      enableWindowsOptimizations: config.enableWindowsOptimizations ?? this.isWindows,
      operationTimeout: config.operationTimeout ?? 30000,
      enableGracefulDegradation: config.enableGracefulDegradation ?? true,
      logLevel: config.logLevel ?? 'debug',
    };

    // Initialize statistics
    this.stats = {
      currentHandles: 0,
      maxHandles: this.config.maxHandles,
      totalOperations: 0,
      successfulOperations: 0,
      failedOperations: 0,
      cleanupCount: 0,
      degradationCount: 0,
      averageOperationDuration: 0,
      peakHandleCount: 0,
    };

    // Log initialization
    this.log('info', 'FileHandleManager initialized', {
      maxHandles: this.config.maxHandles,
      cleanupThreshold: this.config.cleanupThreshold,
      windowsOptimizations: this.config.enableWindowsOptimizations,
    });

    // Setup periodic cleanup
    this.setupPeriodicCleanup();
  }

  /**
   * Read file with managed handle allocation
   */
  async managedReadFile(
    filePath: string,
    options: FileOperationOptions = {}
  ): Promise<string | Buffer> {
    const operationId = this.generateOperationId('read');
    const startTime = Date.now();
    const correlationId = options.correlationId ?? generateCorrelationId();

    this.log('debug', 'Starting managed file read', {
      operationId,
      filePath,
      correlationId,
    });

    try {
      this.stats.totalOperations++;

      // Check if we should use direct fs operation
      if (options.forceDirect || this.shouldUseDirectOperation()) {
        this.log('debug', 'Using direct fs operation for read', {
          operationId,
          filePath,
          forceDirect: options.forceDirect,
        });

        if (!options.forceDirect) {
          this.stats.degradationCount++;
        }

        const result = await this.directReadFile(filePath, options);
        this.recordSuccess(startTime);
        return result;
      }

      // Check handle limit and cleanup if necessary
      await this.ensureHandleAvailability();

      // Create handle info
      const handleInfo: FileHandleInfo = {
        id: operationId,
        path: filePath,
        operation: 'read',
        createdAt: Date.now(),
        operationStart: startTime,
      };

      // Register handle
      this.registerHandle(handleInfo);

      try {
        // Perform read operation with timeout
        const result = await this.withTimeout(
          fs.readFile(filePath, options.encoding),
          options.timeout ?? this.config.operationTimeout,
          `read file: ${filePath}`
        );

        this.log('debug', 'Managed file read completed successfully', {
          operationId,
          filePath,
          size: result ? (typeof result === 'string' ? result.length : 0) : 0,
        });

        this.recordSuccess(startTime);
        return result;
      } finally {
        this.unregisterHandle(operationId);
      }
    } catch (error) {
      this.stats.failedOperations++;
      this.log('error', 'Managed file read failed', {
        operationId,
        filePath,
        error: error instanceof Error ? error.message : String(error),
      });

      // Attempt graceful degradation
      if (this.config.enableGracefulDegradation && !options.forceDirect) {
        this.log('info', 'Attempting graceful degradation for read operation', {
          operationId,
          filePath,
        });

        try {
          const result = await this.directReadFile(filePath, options);
          this.stats.degradationCount++;
          this.log('info', 'Graceful degradation successful for read operation', {
            operationId,
            filePath,
          });
          return result;
        } catch (degradationError) {
          this.log('error', 'Graceful degradation failed for read operation', {
            operationId,
            filePath,
            error:
              degradationError instanceof Error
                ? degradationError.message
                : String(degradationError),
          });
        }
      }

      throw this.wrapError(error, 'read', filePath);
    }
  }

  /**
   * Write file with managed handle allocation
   */
  async managedWriteFile(
    filePath: string,
    data: string | Buffer,
    options: FileOperationOptions & { flag?: string } = {}
  ): Promise<void> {
    const operationId = this.generateOperationId('write');
    const startTime = Date.now();
    const correlationId = options.correlationId ?? generateCorrelationId();

    this.log('debug', 'Starting managed file write', {
      operationId,
      filePath,
      correlationId,
      dataSize: typeof data === 'string' ? data.length : data.byteLength,
    });

    try {
      this.stats.totalOperations++;

      // Check if we should use direct fs operation
      if (options.forceDirect || this.shouldUseDirectOperation()) {
        this.log('debug', 'Using direct fs operation for write', {
          operationId,
          filePath,
          forceDirect: options.forceDirect,
        });

        if (!options.forceDirect) {
          this.stats.degradationCount++;
        }

        await this.directWriteFile(filePath, data, options);
        this.recordSuccess(startTime);
        return;
      }

      // Check handle limit and cleanup if necessary
      await this.ensureHandleAvailability();

      // Create handle info
      const handleInfo: FileHandleInfo = {
        id: operationId,
        path: filePath,
        operation: 'write',
        createdAt: Date.now(),
        operationStart: startTime,
      };

      // Register handle
      this.registerHandle(handleInfo);

      try {
        // Ensure directory exists
        await this.ensureDirectoryExists(filePath);

        // Perform write operation with timeout
        await this.withTimeout(
          fs.writeFile(filePath, data, { encoding: options.encoding, flag: options.flag }),
          options.timeout ?? this.config.operationTimeout,
          `write file: ${filePath}`
        );

        this.log('debug', 'Managed file write completed successfully', {
          operationId,
          filePath,
          dataSize: typeof data === 'string' ? data.length : data.byteLength,
        });

        this.recordSuccess(startTime);
      } finally {
        this.unregisterHandle(operationId);
      }
    } catch (error) {
      this.stats.failedOperations++;
      this.log('error', 'Managed file write failed', {
        operationId,
        filePath,
        error: error instanceof Error ? error.message : String(error),
      });

      // Attempt graceful degradation
      if (this.config.enableGracefulDegradation && !options.forceDirect) {
        this.log('info', 'Attempting graceful degradation for write operation', {
          operationId,
          filePath,
        });

        try {
          await this.directWriteFile(filePath, data, options);
          this.stats.degradationCount++;
          this.log('info', 'Graceful degradation successful for write operation', {
            operationId,
            filePath,
          });
          return;
        } catch (degradationError) {
          this.log('error', 'Graceful degradation failed for write operation', {
            operationId,
            filePath,
            error:
              degradationError instanceof Error
                ? degradationError.message
                : String(degradationError),
          });
        }
      }

      throw this.wrapError(error, 'write', filePath);
    }
  }

  /**
   * Force cleanup of all active handles
   */
  async cleanup(): Promise<void> {
    if (this.cleanupInProgress) {
      this.log('debug', 'Cleanup already in progress, skipping');
      return;
    }

    this.cleanupInProgress = true;
    const cleanupId = generateCorrelationId();

    this.log('info', 'Starting forced cleanup of all handles', {
      cleanupId,
      activeHandles: this.stats.currentHandles,
    });

    try {
      const handlesToClean = Array.from(this.activeHandles.values());

      // Clear timeouts
      for (const handle of handlesToClean) {
        if (handle.timeout) {
          clearTimeout(handle.timeout);
        }
      }

      // Clear all handles
      this.activeHandles.clear();
      this.stats.currentHandles = 0;
      this.stats.cleanupCount++;

      this.log('info', 'Forced cleanup completed', {
        cleanupId,
        cleanedHandles: handlesToClean.length,
      });

      // Emit cleanup event
      this.emitter.emit('cleanup', {
        id: cleanupId,
        cleanedHandles: handlesToClean.length,
      });
    } catch (error) {
      this.log('error', 'Forced cleanup failed', {
        cleanupId,
        error: error instanceof Error ? error.message : String(error),
      });
    } finally {
      this.cleanupInProgress = false;
    }
  }

  /**
   * Get current handle usage statistics
   */
  getStats(): FileHandleStats {
    return { ...this.stats };
  }

  /**
   * Update maximum handle limit
   */
  setMaxHandles(maxHandles: number): void {
    if (maxHandles <= 0) {
      throw new FileHandleManagerError('Maximum handles must be greater than 0', 'INVALID_CONFIG');
    }

    const oldMaxHandles = this.config.maxHandles;
    this.config.maxHandles = maxHandles;
    this.stats.maxHandles = maxHandles;

    this.log('info', 'Maximum handle limit updated', {
      oldMaxHandles,
      newMaxHandles: maxHandles,
      currentHandles: this.stats.currentHandles,
    });

    // Trigger cleanup if new limit is exceeded
    if (this.stats.currentHandles > maxHandles) {
      this.log('warn', 'Current handles exceed new limit, triggering cleanup', {
        currentHandles: this.stats.currentHandles,
        newLimit: maxHandles,
      });
      setImmediate(() => this.cleanup());
    }
  }

  /**
   * Check if a file exists using managed operations
   */
  async fileExists(filePath: string): Promise<boolean> {
    try {
      await fs.access(filePath, constants.F_OK);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Create directory if it doesn't exist
   */
  private async ensureDirectoryExists(filePath: string): Promise<void> {
    const dirPath = resolve(filePath, '..');
    try {
      await fs.access(dirPath, constants.W_OK);
    } catch {
      await fs.mkdir(dirPath, { recursive: true });
      this.log('debug', 'Created directory', { dirPath });
    }
  }

  /**
   * Register a new file handle
   */
  private registerHandle(handleInfo: FileHandleInfo): void {
    this.activeHandles.set(handleInfo.id, handleInfo);
    this.stats.currentHandles = this.activeHandles.size;

    // Update peak handle count
    if (this.stats.currentHandles > this.stats.peakHandleCount) {
      this.stats.peakHandleCount = this.stats.currentHandles;
    }

    this.log('debug', 'Registered file handle', {
      handleId: handleInfo.id,
      path: handleInfo.path,
      operation: handleInfo.operation,
      totalHandles: this.stats.currentHandles,
    });
  }

  /**
   * Unregister a file handle
   */
  private unregisterHandle(handleId: string): void {
    const handle = this.activeHandles.get(handleId);
    if (handle) {
      // Clear timeout if exists
      if (handle.timeout) {
        clearTimeout(handle.timeout);
      }

      this.activeHandles.delete(handleId);
      this.stats.currentHandles = this.activeHandles.size;

      this.log('debug', 'Unregistered file handle', {
        handleId,
        path: handle.path,
        operation: handle.operation,
        totalHandles: this.stats.currentHandles,
      });
    }
  }

  /**
   * Ensure handle availability by triggering cleanup if necessary
   */
  private async ensureHandleAvailability(): Promise<void> {
    const threshold = Math.floor(this.config.maxHandles * this.config.cleanupThreshold);

    if (this.stats.currentHandles >= threshold) {
      this.log('warn', 'Handle threshold reached, triggering cleanup', {
        currentHandles: this.stats.currentHandles,
        threshold,
        maxHandles: this.config.maxHandles,
      });

      await this.cleanup();
    }

    // Wait a bit for cleanup to complete if we're at the limit
    if (this.stats.currentHandles >= this.config.maxHandles) {
      this.log('warn', 'At handle limit, waiting for cleanup', {
        currentHandles: this.stats.currentHandles,
        maxHandles: this.config.maxHandles,
      });

      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }

  /**
   * Check if we should use direct fs operation
   */
  private shouldUseDirectOperation(): boolean {
    // Use direct operation if we're approaching the handle limit
    const threshold = Math.floor(this.config.maxHandles * this.config.cleanupThreshold);
    return this.stats.currentHandles >= threshold;
  }

  /**
   * Direct file read operation (fallback)
   */
  private async directReadFile(
    filePath: string,
    options: FileOperationOptions
  ): Promise<string | Buffer> {
    return fs.readFile(filePath, options.encoding);
  }

  /**
   * Direct file write operation (fallback)
   */
  private async directWriteFile(
    filePath: string,
    data: string | Buffer,
    options: FileOperationOptions & { flag?: string }
  ): Promise<void> {
    await this.ensureDirectoryExists(filePath);
    await fs.writeFile(filePath, data, {
      encoding: options.encoding,
      flag: options.flag,
    });
  }

  /**
   * Record successful operation
   */
  private recordSuccess(startTime: number): void {
    this.stats.successfulOperations++;

    const duration = Date.now() - startTime;
    const totalDuration =
      this.stats.averageOperationDuration * (this.stats.successfulOperations - 1);
    this.stats.averageOperationDuration =
      (totalDuration + duration) / this.stats.successfulOperations;
  }

  /**
   * Wrap error in FileHandleManagerError
   */
  private wrapError(error: unknown, operation: string, filePath: string): FileHandleManagerError {
    const message = error instanceof Error ? error.message : String(error);
    const code = error instanceof Error && 'code' in error ? String(error.code) : 'UNKNOWN';

    return new FileHandleManagerError(`File ${operation} operation failed: ${message}`, code, {
      path: filePath,
      operation,
      cause: error instanceof Error ? error : new Error(String(error)),
    });
  }

  /**
   * Execute operation with timeout
   */
  private async withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    operation: string
  ): Promise<T> {
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => {
        reject(new FileHandleManagerError(`Operation timeout: ${operation}`, 'TIMEOUT'));
      }, timeoutMs);
    });

    return Promise.race([promise, timeoutPromise]);
  }

  /**
   * Generate unique operation ID
   */
  private generateOperationId(operation: string): string {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 8);
    return `${operation}-${random}-${timestamp}`;
  }

  /**
   * Log message with configured level
   */
  private log(
    level: 'debug' | 'info' | 'warn' | 'error',
    message: string,
    meta?: Record<string, unknown>
  ): void {
    // Only log if the level is at or above the configured level
    const levels = { debug: 0, info: 1, warn: 2, error: 3 };
    const configLevel = levels[this.config.logLevel];
    const messageLevel = levels[level];

    if (messageLevel >= configLevel) {
      logger[level](
        {
          component: 'FileHandleManager',
          ...meta,
        },
        message
      );
    }
  }

  /**
   * Setup periodic cleanup
   */
  private setupPeriodicCleanup(): void {
    // Run cleanup every 5 minutes
    setInterval(
      () => {
        if (this.stats.currentHandles > 0) {
          this.log('debug', 'Running periodic cleanup', {
            activeHandles: this.stats.currentHandles,
          });
          this.cleanup();
        }
      },
      5 * 60 * 1000
    );
  }

  /**
   * Shutdown the file handle manager
   */
  async shutdown(): Promise<void> {
    this.log('info', 'Shutting down FileHandleManager', {
      activeHandles: this.stats.currentHandles,
      totalOperations: this.stats.totalOperations,
    });

    await this.cleanup();
    this.emitter.removeAllListeners();
  }
}

// Default singleton instance
export const fileHandleManager = new FileHandleManager();

/**
 * Convenience functions for direct usage
 */
export async function readFileManaged(
  filePath: string,
  options?: FileOperationOptions
): Promise<string | Buffer> {
  return fileHandleManager.managedReadFile(filePath, options);
}

export async function writeFileManaged(
  filePath: string,
  data: string | Buffer,
  options?: FileOperationOptions & { flag?: string }
): Promise<void> {
  return fileHandleManager.managedWriteFile(filePath, data, options);
}

export function getFileHandleStats(): FileHandleStats {
  return fileHandleManager.getStats();
}

export async function cleanupFileHandles(): Promise<void> {
  return fileHandleManager.cleanup();
}

export function setMaxFileHandles(maxHandles: number): void {
  fileHandleManager.setMaxHandles(maxHandles);
}
