/**
 * Global Test Setup for Cortex Memory MCP
 *
 * This file provides global setup for all test suites.
 */

import { performanceCollector } from '../src/monitoring/performance-collector.js';

export async function setup() {
  console.log('🚀 Global test setup starting...');

  // Increase file descriptor limit on Unix-like systems
  if (process.platform !== 'win32') {
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
    info: () => {},   // Suppress info logs
    warn: () => {},   // Suppress warn logs
    error: console.error, // Keep error logs
  };

  console.log('✅ Global test setup completed');
}

export async function teardown() {
  console.log('🧹 Global test teardown starting...');

  // Cleanup performance collector after tests to prevent memory leaks
  performanceCollector.cleanup();

  // Force garbage collection if available
  if (global.gc) {
    global.gc();
  }

  // Small delay to allow cleanup operations to complete
  await new Promise(resolve => setTimeout(resolve, 100));

  console.log('✅ Global test teardown completed');
}