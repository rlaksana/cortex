/**
 * Global MCP Test Setup
 *
 * This file runs once before all test suites to set up the global test environment.
 */

import { spawn } from 'child_process';
import { TestUtilities } from './mcp-test-setup';

export async function setup() {
  console.log('🚀 Setting up global MCP test environment...');

  // Ensure test Qdrant instance is running (if using real Qdrant)
  const qdrantUrl = process.env.QDRANT_URL || 'http://localhost:6333';

  try {
    // Health check for Qdrant (skip if using mock)
    if (process.env.USE_REAL_QDRANT !== 'false') {
      console.log(`🏥 Checking Qdrant health at ${qdrantUrl}...`);
      // Could add real health check here if needed
    }
  } catch (error) {
    console.warn('⚠️ Qdrant not available, using mock client for tests');
  }

  // Initialize test data directories
  const testDirs = ['./artifacts/mcp-tests', './artifacts/mcp-logs', './artifacts/mcp-temp'];

  for (const dir of testDirs) {
    try {
      await TestUtilities.withTimeout(
        import('fs').then(fs => fs.promises.mkdir(dir, { recursive: true })),
        5000
      );
      console.log(`📁 Created test directory: ${dir}`);
    } catch (error) {
      console.warn(`⚠️ Failed to create test directory ${dir}:`, error);
    }
  }

  // Set up test environment variables
  process.env.MCP_TEST_MODE = 'true';
  process.env.MCP_TEST_TIMEOUT = '30000';
  process.env.MCP_LOG_LEVEL = 'debug';

  console.log('✅ Global MCP test environment setup completed');
}

export async function teardown() {
  console.log('🧹 Tearing down global MCP test environment...');

  // Cleanup any leftover test processes
  try {
    // Kill any remaining MCP server processes
    if (process.platform !== 'win32') {
      const { exec } = await import('child_process');
      exec('pkill -f "node.*dist/index.js" || true');
    } else {
      // Windows cleanup
      const { exec } = await import('child_process');
      exec('taskkill /F /IM node.exe /FI "WINDOWTITLE eq *cortex*" || true');
    }
  } catch (error) {
    console.warn('⚠️ Failed to cleanup test processes:', error);
  }

  // Cleanup temporary test files
  try {
    const { execSync } = await import('child_process');
    if (process.platform !== 'win32') {
      execSync('find ./artifacts/mcp-temp -type f -mtime +1 -delete 2>/dev/null || true');
    }
  } catch (error) {
    console.warn('⚠️ Failed to cleanup temp files:', error);
  }

  console.log('✅ Global MCP test environment teardown completed');
}

// Run setup and teardown
setup().catch(error => {
  console.error('❌ Global MCP test setup failed:', error);
  process.exit(1);
});

// Register teardown for graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🛑 Received SIGINT, tearing down...');
  await teardown();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\n🛑 Received SIGTERM, tearing down...');
  await teardown();
  process.exit(0);
});