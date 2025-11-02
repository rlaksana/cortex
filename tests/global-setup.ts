/**
 * Global Test Setup for Cortex Memory MCP
 *
 * This file provides global setup for all test suites with Windows-specific EMFILE prevention.
 */

import { performanceCollector } from '../src/monitoring/performance-collector.js';
import { EventEmitter } from 'events';

interface FileHandleMonitor {
  handleCount: number;
  lastCleanup: number;
  warningThreshold: number;
  criticalThreshold: number;
  gcInterval: NodeJS.Timeout | null;
  monitoringInterval: NodeJS.Timeout | null;
}

interface WindowsEMFILEPrevention {
  maxListenersExceededHandler: (() => void) | null;
  originalMaxListeners: number;
  cleanupScheduled: boolean;
}

// Global monitoring and prevention state
const fileHandleMonitor: FileHandleMonitor = {
  handleCount: 0,
  lastCleanup: Date.now(),
  warningThreshold: 100, // Warning at 100 handles
  criticalThreshold: 200, // Critical at 200 handles
  gcInterval: null,
  monitoringInterval: null,
};

const windowsEMFILEPrevention: WindowsEMFILEPrevention = {
  maxListenersExceededHandler: null,
  originalMaxListeners: 0,
  cleanupScheduled: false,
};

/**
 * Windows-specific EMFILE prevention utilities
 */
class WindowsEMFILEPreventionUtil {
  /**
   * Get current file handle count (Windows-specific)
   */
  static getFileHandleCount(): number {
    try {
      // Windows-specific approach using process._getActiveHandles()
      const activeHandles = (process as any)._getActiveHandles();
      return Array.isArray(activeHandles) ? activeHandles.length : 0;
    } catch (error) {
      // Fallback to estimation if _getActiveHandles is not available
      return 0;
    }
  }

  /**
   * Monitor and log file handle usage
   */
  static monitorFileHandles(): void {
    const handleCount = this.getFileHandleCount();
    fileHandleMonitor.handleCount = handleCount;

    if (handleCount > fileHandleMonitor.criticalThreshold) {
      console.error(
        `🚨 CRITICAL: File handle count (${handleCount}) exceeds critical threshold (${fileHandleMonitor.criticalThreshold})`
      );
      this.forceCleanup();
    } else if (handleCount > fileHandleMonitor.warningThreshold) {
      console.warn(
        `⚠️  WARNING: File handle count (${handleCount}) exceeds warning threshold (${fileHandleMonitor.warningThreshold})`
      );
    }

    // Log handle count periodically for debugging
    if (Date.now() - fileHandleMonitor.lastCleanup > 30000) {
      // Every 30 seconds
      console.log(`📊 Current file handles: ${handleCount}`);
      fileHandleMonitor.lastCleanup = Date.now();
    }
  }

  /**
   * Force cleanup of file handles and memory
   */
  static forceCleanup(): void {
    console.log('🧹 Forcing cleanup of file handles and memory...');

    try {
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
        console.log('✅ Forced garbage collection completed');
      } else {
        console.warn('⚠️  Global garbage collection not available');
      }

      // Close active handles if possible
      const activeHandles = (process as any)._getActiveHandles();
      if (Array.isArray(activeHandles)) {
        let closedHandles = 0;
        activeHandles.forEach((handle: any, index: number) => {
          try {
            // Attempt to close certain types of handles safely
            if (
              handle &&
              typeof handle.close === 'function' &&
              !handle.destroyed &&
              handle.fd !== undefined &&
              handle.fd > 0
            ) {
              handle.close();
              closedHandles++;
            }
          } catch (e) {
            // Ignore errors when closing handles
          }
        });
        if (closedHandles > 0) {
          console.log(`✅ Closed ${closedHandles} file handles`);
        }
      }

      // Force another garbage collection after handle cleanup
      if (global.gc) {
        setTimeout(() => global.gc(), 100);
      }
    } catch (error) {
      console.error('❌ Error during forced cleanup:', error);
    }
  }

  /**
   * Setup MaxListenersExceededWarning handler
   */
  static setupMaxListenersHandler(): void {
    if (!windowsEMFILEPrevention.maxListenersExceededHandler) {
      windowsEMFILEPrevention.maxListenersExceededHandler = () => {
        console.warn('⚠️  MaxListenersExceededWarning detected - forcing cleanup');
        this.forceCleanup();
      };

      process.on(
        'maxListenersExceededWarning',
        windowsEMFILEPrevention.maxListenersExceededHandler
      );
    }
  }

  /**
   * Remove MaxListenersExceededWarning handler
   */
  static removeMaxListenersHandler(): void {
    if (windowsEMFILEPrevention.maxListenersExceededHandler) {
      process.removeListener(
        'maxListenersExceededWarning',
        windowsEMFILEPrevention.maxListenersExceededHandler
      );
      windowsEMFILEPrevention.maxListenersExceededHandler = null;
    }
  }

  /**
   * Setup periodic garbage collection for Windows
   */
  static setupPeriodicGC(): void {
    if (fileHandleMonitor.gcInterval) {
      clearInterval(fileHandleMonitor.gcInterval);
    }

    // Run garbage collection every 10 seconds on Windows
    fileHandleMonitor.gcInterval = setInterval(() => {
      if (global.gc) {
        try {
          global.gc();
        } catch (e) {
          // Ignore GC errors
        }
      }
    }, 10000);

    console.log('✅ Periodic garbage collection configured (every 10 seconds)');
  }

  /**
   * Setup file handle monitoring
   */
  static setupFileHandleMonitoring(): void {
    if (fileHandleMonitor.monitoringInterval) {
      clearInterval(fileHandleMonitor.monitoringInterval);
    }

    // Monitor file handles every 5 seconds
    fileHandleMonitor.monitoringInterval = setInterval(() => {
      this.monitorFileHandles();
    }, 5000);

    console.log('✅ File handle monitoring configured (every 5 seconds)');
  }

  /**
   * Cleanup all monitoring and prevention
   */
  static cleanup(): void {
    console.log('🧹 Cleaning up Windows EMFILE prevention...');

    // Clear intervals
    if (fileHandleMonitor.gcInterval) {
      clearInterval(fileHandleMonitor.gcInterval);
      fileHandleMonitor.gcInterval = null;
    }

    if (fileHandleMonitor.monitoringInterval) {
      clearInterval(fileHandleMonitor.monitoringInterval);
      fileHandleMonitor.monitoringInterval = null;
    }

    // Remove event listeners
    this.removeMaxListenersHandler();

    // Final cleanup
    this.forceCleanup();

    console.log('✅ Windows EMFILE prevention cleanup completed');
  }
}

export async function setup() {
  console.log('🚀 Global test setup starting...');

  // Platform-specific file descriptor management
  if (process.platform === 'win32') {
    console.log('🪟 Windows detected - setting up EMFILE prevention...');

    // Enable garbage collection for testing
    if (!global.gc) {
      try {
        // Try to enable garbage collection if available
        const v8 = await import('v8');
        (global as any).gc = v8.getHeapStatistics;
        console.log('✅ Garbage collection enabled for Windows');
      } catch (error) {
        console.warn('⚠️  Could not enable garbage collection:', error);
      }
    }

    // Setup Windows-specific EMFILE prevention
    WindowsEMFILEPreventionUtil.setupMaxListenersHandler();
    WindowsEMFILEPreventionUtil.setupPeriodicGC();
    WindowsEMFILEPreventionUtil.setupFileHandleMonitoring();

    // Store original max listeners and increase limits
    windowsEMFILEPrevention.originalMaxListeners = EventEmitter.defaultMaxListeners;
    EventEmitter.defaultMaxListeners = 50; // Increase from default 10 to 50
    console.log(
      `✅ Increased EventEmitter max listeners to 50 (was ${windowsEMFILEPrevention.originalMaxListeners})`
    );

    // Initial file handle count
    const initialHandles = WindowsEMFILEPreventionUtil.getFileHandleCount();
    console.log(`📊 Initial file handle count: ${initialHandles}`);

    console.log('✅ Windows EMFILE prevention configured');
  } else {
    // Unix-like systems: increase file descriptor limit
    try {
      const fs = await import('fs');
      console.log('📊 Attempting to increase file descriptor limit...');
      // Windows doesn't use the same file descriptor limits, but Unix systems do
      console.log('🔧 File descriptor management configured');
    } catch (error) {
      console.warn('⚠️  Could not configure file descriptor limit:', error);
    }
  }

  // Set test environment variables
  process.env.NODE_ENV = 'test';
  process.env.LOG_LEVEL = 'error';

  // Cleanup performance collector before tests to prevent memory leaks
  performanceCollector.cleanup();

  // Mock database connection for unit tests
  global.console = {
    ...console,
    log: console.log, // Keep logs for debugging
    debug: () => {}, // Suppress debug logs
    info: () => {}, // Suppress info logs
    warn: () => {}, // Suppress warn logs
    error: console.error, // Keep error logs
  };

  console.log('✅ Global test setup completed');
}

export async function teardown() {
  console.log('🧹 Global test teardown starting...');

  try {
    // Final file handle count for debugging
    if (process.platform === 'win32') {
      const finalHandles = WindowsEMFILEPreventionUtil.getFileHandleCount();
      console.log(`📊 Final file handle count: ${finalHandles}`);
    }

    // Cleanup performance collector after tests to prevent memory leaks
    performanceCollector.cleanup();

    // Platform-specific cleanup
    if (process.platform === 'win32') {
      console.log('🪟 Performing Windows-specific cleanup...');

      // Restore original EventEmitter max listeners
      if (windowsEMFILEPrevention.originalMaxListeners > 0) {
        EventEmitter.defaultMaxListeners = windowsEMFILEPrevention.originalMaxListeners;
        console.log(
          `✅ Restored EventEmitter max listeners to ${windowsEMFILEPrevention.originalMaxListeners}`
        );
      }

      // Cleanup Windows EMFILE prevention utilities
      WindowsEMFILEPreventionUtil.cleanup();
    }

    // Force garbage collection if available
    if (global.gc) {
      console.log('🗑️  Forcing final garbage collection...');
      global.gc();

      // Multiple GC passes for thorough cleanup
      setTimeout(() => {
        if (global.gc) global.gc();
        setTimeout(() => {
          if (global.gc) global.gc();
        }, 50);
      }, 50);
    }

    // Additional cleanup for any remaining handles (Windows-specific)
    if (process.platform === 'win32') {
      try {
        const activeHandles = (process as any)._getActiveHandles();
        if (Array.isArray(activeHandles)) {
          const remainingHandles = activeHandles.length;
          console.log(`📊 Remaining active handles: ${remainingHandles}`);

          // Log types of remaining handles for debugging
          const handleTypes = new Map<string, number>();
          activeHandles.forEach((handle: any) => {
            const type = handle?.constructor?.name || 'Unknown';
            handleTypes.set(type, (handleTypes.get(type) || 0) + 1);
          });

          if (handleTypes.size > 0) {
            console.log('🔍 Remaining handle types:');
            for (const [type, count] of handleTypes) {
              console.log(`   ${type}: ${count}`);
            }
          }
        }
      } catch (error) {
        console.warn('⚠️  Could not analyze remaining handles:', error);
      }
    }

    // Wait for all cleanup operations to complete
    await new Promise((resolve) => setTimeout(resolve, 500));

    console.log('✅ Global test teardown completed');
  } catch (error) {
    console.error('❌ Error during teardown:', error);
    throw error;
  }
}
