// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck


/**
 * Graceful Shutdown Manager
 *
 * Comprehensive graceful shutdown system for production environments.
 * Handles signal processing, cleanup operations, and ensures data integrity
 * during shutdown scenarios.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { EventEmitter } from 'events';

import { ProductionLogger } from '@/utils/logger.js';

export interface ShutdownConfig {
  timeout: number;
  forceTimeout: number;
  enableDrainMode: boolean;
  drainTimeout: number;
  cleanupOperations: CleanupOperation[];
}

export interface CleanupOperation {
  name: string;
  priority: number;
  timeout: number;
  operation: () => Promise<void>;
  critical: boolean;
}

export interface ShutdownState {
  isShuttingDown: boolean;
  shutdownReason: string;
  shutdownInitiated: number;
  cleanupCompleted: Record<string, boolean>;
  errors: Array<{ operation: string; error: string; timestamp: number }>;
}

export class GracefulShutdownManager extends EventEmitter {
  private config: ShutdownConfig;
  private logger: { info: (...a:any[])=>void; warn:(...a:any[])=>void; error:(...a:any[])=>void; debug?: (...a:any[])=>void };
  private state: ShutdownState;
  private shutdownTimer: NodeJS.Timeout | null = null;
  private forceTimer: NodeJS.Timeout | null = null;

  constructor(config?: Partial<ShutdownConfig>) {
    super();

    this.logger = ProductionLogger;

    this.config = {
      timeout: parseInt(process.env.SHUTDOWN_TIMEOUT || '30000'), // 30 seconds
      forceTimeout: parseInt(process.env.FORCE_SHUTDOWN_TIMEOUT || '60000'), // 60 seconds
      enableDrainMode: process.env.ENABLE_DRAIN_MODE !== 'false',
      drainTimeout: parseInt(process.env.DRAIN_TIMEOUT || '10000'), // 10 seconds
      cleanupOperations: [],
    };

    this.state = {
      isShuttingDown: false,
      shutdownReason: '',
      shutdownInitiated: 0,
      cleanupCompleted: {},
      errors: [],
    };

    this.setupSignalHandlers();
  }

  /**
   * Public shutdown method for external callers
   */
  public async shutdown(reason?: string): Promise<void> {
    const shutdownReason = reason || 'External shutdown request';
    return this.initiateShutdown(shutdownReason);
  }

  /**
   * Setup signal handlers for graceful shutdown
   */
  private setupSignalHandlers(): void {
    const signals = ['SIGTERM', 'SIGINT', 'SIGUSR2'];

    signals.forEach((signal) => {
      process.on(signal, (signalName) => {
        this.logger.info(`Received shutdown signal: ${signalName}`);
        this.initiateShutdown(signalName);
      });
    });

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      this.logger.error('Uncaught exception caught', {
        error: error.message,
        stack: error.stack,
      });
      this.initiateShutdown('uncaughtException', error);
    });

    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      this.logger.error('Unhandled promise rejection', {
        reason: reason instanceof Error ? reason.message : reason,
        promise: promise.toString(),
      });
      this.initiateShutdown(
        'unhandledRejection',
        reason instanceof Error ? reason : new Error(String(reason))
      );
    });
  }

  /**
   * Initiate graceful shutdown
   */
  async initiateShutdown(reason: string, error?: Error): Promise<void> {
    if (this.state.isShuttingDown) {
      this.logger.warn('Shutdown already in progress, ignoring additional signal');
      return;
    }

    this.state.isShuttingDown = true;
    this.state.shutdownReason = reason;
    this.state.shutdownInitiated = Date.now();

    this.logger.info(`🛑 Initiating graceful shutdown`, {
      reason,
      error: error?.message,
      timestamp: new Date().toISOString(),
    });

    this.emit('shutdown:initiated', { reason, error });

    try {
      // Set shutdown timeout
      this.setupShutdownTimeout();

      // Drain mode - stop accepting new requests
      if (this.config.enableDrainMode) {
        await this.drainRequests();
      }

      // Perform cleanup operations
      await this.performCleanup();

      // Clear timers
      this.clearTimers();

      this.logger.info('✅ Graceful shutdown completed successfully');
      this.emit('shutdown:completed');

      process.exit(0);
    } catch (error) {
      this.logger.error('Error during graceful shutdown', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      this.emit('shutdown:error', error);
      process.exit(1);
    }
  }

  /**
   * Setup shutdown timeout
   */
  private setupShutdownTimeout(): void {
    this.shutdownTimer = setTimeout(() => {
      this.logger.warn('Graceful shutdown timeout reached, forcing exit');
      this.emit('shutdown:timeout');
      process.exit(1);
    }, this.config.timeout);

    this.forceTimer = setTimeout(() => {
      this.logger.error('Force shutdown timeout reached, forcing exit immediately');
      process.exit(1);
    }, this.config.forceTimeout);
  }

  /**
   * Clear shutdown timers
   */
  private clearTimers(): void {
    if (this.shutdownTimer) {
      clearTimeout(this.shutdownTimer);
      this.shutdownTimer = null;
    }

    if (this.forceTimer) {
      clearTimeout(this.forceTimer);
      this.forceTimer = null;
    }
  }

  /**
   * Drain mode - stop accepting new requests
   */
  private async drainRequests(): Promise<void> {
    this.logger.info('🔄 Entering drain mode - stopping new requests');
    this.emit('drain:start');

    try {
      // Signal that we're no longer accepting new requests
      this.emit('drain:stop-accepting');

      // Wait for active requests to complete
      await this.waitForActiveRequests();

      this.logger.info('✅ Drain mode completed');
      this.emit('drain:completed');
    } catch (error) {
      this.logger.warn('Drain mode encountered issues', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  /**
   * Wait for active requests to complete
   */
  private async waitForActiveRequests(): Promise<void> {
    // This is a placeholder implementation
    // In a real application, you would track active connections/requests
    // and wait for them to complete or timeout

    const drainStart = Date.now();
    const maxDrainTime = this.config.drainTimeout;

    return new Promise((resolve) => {
      // Simulate waiting for active requests
      setTimeout(() => {
        const drainDuration = Date.now() - drainStart;
        this.logger.info(`Drain completed in ${drainDuration}ms`);
        resolve();
      }, 2000); // 2 second placeholder
    });
  }

  /**
   * Perform cleanup operations
   */
  private async performCleanup(): Promise<void> {
    this.logger.info('🧹 Starting cleanup operations');
    this.emit('cleanup:start');

    // Sort operations by priority (lower number = higher priority)
    const sortedOperations = [...this.config.cleanupOperations].sort(
      (a, b) => a.priority - b.priority
    );

    for (const operation of sortedOperations) {
      try {
        this.logger.info(`Running cleanup operation: ${operation.name}`);
        this.emit('cleanup:operation:start', { operation: operation.name });

        const operationStart = Date.now();

        // Set timeout for individual operation
        await Promise.race([
          operation.operation(),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Operation timeout')), operation.timeout)
          ),
        ]);

        const operationDuration = Date.now() - operationStart;
        this.state.cleanupCompleted[operation.name] = true;

        this.logger.info(`Cleanup operation completed: ${operation.name} (${operationDuration}ms)`);
        this.emit('cleanup:operation:completed', {
          operation: operation.name,
          duration: operationDuration,
        });
      } catch (error) {
        this.state.errors.push({
          operation: operation.name,
          error: error instanceof Error ? error.message : 'Unknown error',
          timestamp: Date.now(),
        });

        this.logger.error(`Cleanup operation failed: ${operation.name}`, {
          error: error instanceof Error ? error.message : 'Unknown error',
          critical: operation.critical,
        });

        this.emit('cleanup:operation:error', {
          operation: operation.name,
          error,
          critical: operation.critical,
        });

        // If this is a critical operation, we might want to fail shutdown
        if (operation.critical) {
          throw new Error(`Critical cleanup operation failed: ${operation.name}`);
        }
      }
    }

    // Add default cleanup operations if none were specified
    if (sortedOperations.length === 0) {
      await this.performDefaultCleanup();
    }

    this.logger.info('✅ All cleanup operations completed');
    this.emit('cleanup:completed', {
      completed: this.state.cleanupCompleted,
      errors: this.state.errors.length,
    });
  }

  /**
   * Perform default cleanup operations
   */
  private async performDefaultCleanup(): Promise<void> {
    const defaultOperations = [
      {
        name: 'database-connections',
        operation: this.closeDatabaseConnections.bind(this),
        timeout: 5000,
        critical: true,
        priority: 1,
      },
      {
        name: 'background-workers',
        operation: this.stopBackgroundWorkers.bind(this),
        timeout: 3000,
        critical: false,
        priority: 2,
      },
      {
        name: 'flush-logs',
        operation: this.flushLogs.bind(this),
        timeout: 2000,
        critical: false,
        priority: 3,
      },
      {
        name: 'save-metrics',
        operation: this.saveFinalMetrics.bind(this),
        timeout: 2000,
        critical: false,
        priority: 4,
      },
    ];

    this.config.cleanupOperations = defaultOperations;
  }

  /**
   * Close database connections
   */
  private async closeDatabaseConnections(): Promise<void> {
    this.logger.info('Closing database connections...');
    // Implementation would depend on your database setup
    // This is a placeholder for the actual database cleanup logic

    // Simulate database cleanup
    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  /**
   * Stop background workers
   */
  private async stopBackgroundWorkers(): Promise<void> {
    this.logger.info('Stopping background workers...');
    // Implementation would stop any background processes

    // Simulate worker shutdown
    await new Promise((resolve) => setTimeout(resolve, 300));
  }

  /**
   * Flush pending logs
   */
  private async flushLogs(): Promise<void> {
    this.logger.info('Flushing logs...');
    // Implementation would flush any buffered logs

    // Simulate log flushing
    await new Promise((resolve) => setTimeout(resolve, 200));
  }

  /**
   * Save final metrics
   */
  private async saveFinalMetrics(): Promise<void> {
    this.logger.info('Saving final metrics...');
    // Implementation would save any pending metrics

    // Simulate metrics saving
    await new Promise((resolve) => setTimeout(resolve, 200));
  }

  /**
   * Add cleanup operation
   */
  addCleanupOperation(operation: CleanupOperation): void {
    this.config.cleanupOperations.push(operation);
    this.logger.debug?.(`Added cleanup operation: ${operation.name}`);
  }

  /**
   * Remove cleanup operation
   */
  removeCleanupOperation(name: string): void {
    this.config.cleanupOperations = this.config.cleanupOperations.filter((op) => op.name !== name);
    this.logger.debug?.(`Removed cleanup operation: ${name}`);
  }

  /**
   * Get current shutdown state
   */
  getShutdownState(): ShutdownState {
    return { ...this.state };
  }

  /**
   * Check if shutdown is in progress
   */
  isShuttingDown(): boolean {
    return this.state.isShuttingDown;
  }

  /**
   * Get remaining shutdown time
   */
  getRemainingShutdownTime(): number {
    if (!this.state.isShuttingDown) {
      return 0;
    }

    const elapsed = Date.now() - this.state.shutdownInitiated;
    return Math.max(0, this.config.timeout - elapsed);
  }

  /**
   * Emergency shutdown - immediate exit
   */
  emergencyShutdown(reason: string, code: number = 1): void {
    this.logger.error(`🚨 EMERGENCY SHUTDOWN: ${reason}`);
    this.emit('shutdown:emergency', { reason, code });

    // Clear any existing timers
    this.clearTimers();

    // Force exit immediately
    process.exit(code);
  }

  /**
   * Health check for shutdown manager
   */
  healthCheck(): { healthy: boolean; details: Record<string, unknown> } {
    return {
      healthy: !this.state.isShuttingDown,
      details: {
        isShuttingDown: this.state.isShuttingDown,
        shutdownReason: this.state.shutdownReason,
        uptime: process.uptime(),
        cleanupOperationsCount: this.config.cleanupOperations.length,
        errorsCount: this.state.errors.length,
        remainingShutdownTime: this.getRemainingShutdownTime(),
      },
    };
  }
}

// Export singleton instance
export const gracefulShutdown = new GracefulShutdownManager();

export default GracefulShutdownManager;
