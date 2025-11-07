#!/usr/bin/env node

/**
 * Cortex Memory MCP Server - Silent Entry Point
 *
 * This is the silent entry point that suppresses startup logs
 * for clean MCP transport operation while using the standardized
 * factory pattern for consistent initialization.
 *
 * Features:
 * - Complete log suppression during startup and operation
 * - Factory pattern for consistent server creation
 * - Enhanced error handling for silent mode
 * - Graceful shutdown with proper console restoration
 * - Debug mode for troubleshooting
 *
 * @author Cortex Team
 * @version 2.0.1
 * @since 2025
 */

import { createMcpServer } from './entry-point-factory.js';

interface SilentConfig {
  debugMode: boolean;
  captureLogs: boolean;
  restoreOnError: boolean;
}

class SilentModeManager {
  private originalConsoleError: typeof console.error;
  private originalConsoleLog: typeof console.log;
  private originalConsoleWarn: typeof console.warn;
  private originalConsoleDebug: typeof console.debug;
  private capturedLogs: string[] = [];
  private config: SilentConfig;

  constructor(config: SilentConfig) {
    this.config = config;
    this.originalConsoleError = console.error;
    this.originalConsoleLog = console.log;
    this.originalConsoleWarn = console.warn;
    this.originalConsoleDebug = console.debug;
  }

  public enableSilentMode(): void {
    if (this.config.debugMode) {
      return; // Don't suppress logs in debug mode
    }

    console.error = (...args: any[]) => {
      if (this.config.captureLogs) {
        this.capturedLogs.push(`[ERROR] ${args.join(' ')}`);
      }
    };

    console.log = (...args: any[]) => {
      if (this.config.captureLogs) {
        this.capturedLogs.push(`[INFO] ${args.join(' ')}`);
      }
    };

    console.warn = (...args: any[]) => {
      if (this.config.captureLogs) {
        this.capturedLogs.push(`[WARN] ${args.join(' ')}`);
      }
    };

    console.debug = (...args: any[]) => {
      if (this.config.captureLogs) {
        this.capturedLogs.push(`[DEBUG] ${args.join(' ')}`);
      }
    };
  }

  public restoreConsole(): void {
    console.error = this.originalConsoleError;
    console.log = this.originalConsoleLog;
    console.warn = this.originalConsoleWarn;
    console.debug = this.originalConsoleDebug;
  }

  public getCapturedLogs(): string[] {
    return [...this.capturedLogs];
  }

  public clearCapturedLogs(): void {
    this.capturedLogs = [];
  }

  public debugLog(message: string, ...args: any[]): void {
    if (this.config.debugMode) {
      this.originalConsoleError(`[SILENT-DEBUG] ${message}`, ...args);
    }
  }
}

async function main() {
  // Parse command line arguments for debug mode
  const debugMode = process.argv.includes('--debug') || process.env.CORTEX_SILENT_DEBUG === 'true';

  const config: SilentConfig = {
    debugMode,
    captureLogs: !debugMode,
    restoreOnError: true
  };

  const silentManager = new SilentModeManager(config);
  silentManager.enableSilentMode();

  silentManager.debugLog('Starting Cortex Memory MCP Server in silent mode...');

  try {
    // Create server instance with silent configuration
    const server = createMcpServer({
      logger: {
        level: 'error', // Only log errors in silent mode
        silent: true,
        prefix: debugMode ? 'CORTEX-SILENT-DEBUG' : 'CORTEX-SILENT'
      }
    });

    silentManager.debugLog('Server instance created, initializing...');

    // Initialize the server
    await server.initialize();

    silentManager.debugLog('Server initialized, starting transport...');

    // Start the transport
    await server.startTransport();

    // Restore console if we're in debug mode
    if (debugMode) {
      silentManager.restoreConsole();
      console.log('🤫 Silent MCP Server started successfully (debug mode)');
      console.log('Available tools: memory_store, memory_find, system_status');
    }

    silentManager.debugLog('Silent MCP Server started and ready for connections');

  } catch (error) {
    silentManager.debugLog('Server startup failed:', error);

    // Restore console output on error if configured
    if (config.restoreOnError || debugMode) {
      silentManager.restoreConsole();
    }

    // Log captured logs if in debug mode
    if (debugMode && config.captureLogs) {
      const capturedLogs = silentManager.getCapturedLogs();
      if (capturedLogs.length > 0) {
        console.error('📋 Captured logs during startup:');
        capturedLogs.forEach((log, index) => {
          console.error(`  ${index + 1}. ${log}`);
        });
      }
    }

    console.error('❌ Failed to start Cortex Memory MCP Server (Silent):', error);
    process.exit(1);
  }
}

// Handle process termination gracefully
process.on('SIGINT', () => {
  if (process.env.CORTEX_SILENT_DEBUG === 'true') {
    console.error('🛑 Silent MCP Server received SIGINT, shutting down...');
  }
  process.exit(0);
});

process.on('SIGTERM', () => {
  if (process.env.CORTEX_SILENT_DEBUG === 'true') {
    console.error('🛑 Silent MCP Server received SIGTERM, shutting down...');
  }
  process.exit(0);
});

// Handle uncaught exceptions in silent mode
process.on('uncaughtException', (error) => {
  // Always restore console for uncaught exceptions
  console.error = console.error;
  console.log = console.log;
  console.warn = console.warn;
  console.debug = console.debug;

  console.error('💥 Uncaught exception in Silent MCP Server:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  // Always restore console for unhandled rejections
  console.error = console.error;
  console.log = console.log;
  console.warn = console.warn;
  console.debug = console.debug;

  console.error('💥 Unhandled rejection in Silent MCP Server at:', promise, 'reason:', reason);
  process.exit(1);
});

// Self-executing block for direct running
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    // Restore console output before final error
    console.error = console.error;
    console.log = console.log;
    console.warn = console.warn;
    console.debug = console.debug;

    console.error('💥 Silent MCP Server startup failed catastrophically:', error);
    process.exit(1);
  });
}

export { main, SilentModeManager };