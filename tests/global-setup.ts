/**
 * Global Test Setup for Cortex Memory MCP
 *
 * This file provides global setup for all test suites.
 */

export async function setup() {
  console.log('🚀 Global test setup starting...');

  // Set test environment variables
  process.env.NODE_ENV = 'test';
  process.env.LOG_LEVEL = 'error';

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
  console.log('🧹 Global test teardown completed');
}