#!/usr/bin/env node

// EMERGENCY ROLLBACK: Core entry point type compatibility issues

/**
 * Cortex Memory MCP Server - Main Entry Point
 *
 * This is the main entry point for the Cortex Memory MCP Server.
 * It uses the standardized factory pattern for consistent initialization,
 * proper error handling, and graceful shutdown.
 *
 * Features:
 * - Uses factory pattern for consistent server creation
 * - Comprehensive error handling and recovery
 * - Proper graceful shutdown handling
 * - Verbose logging and monitoring
 * - Both simple and advanced functionality
 *
 * @author Cortex Team
 * @version 2.0.1
 * @since 2025
 */

import { createMcpServer } from './entry-point-factory.js';

// Start the server
async function main() {
  try {
    // Validate log level with proper typing
    const validLogLevels = ['error', 'warn', 'info', 'debug'] as const;
    type LogLevel = typeof validLogLevels[number];

    const logLevel: LogLevel = process.env.LOG_LEVEL &&
      validLogLevels.includes(process.env.LOG_LEVEL.toLowerCase() as LogLevel)
      ? (process.env.LOG_LEVEL.toLowerCase() as LogLevel)
      : 'info';

    // Create server instance with verbose configuration
    const server = createMcpServer({
      logger: {
        level: logLevel,
        silent: false,
        prefix: 'CORTEX-MAIN',
      },
    });

    // Initialize the server
    await server.initialize();

    // Start the transport
    await server.startTransport();

    // Server is now running
    server.getLogger().info('Cortex Memory MCP Server started successfully!');
    server.getLogger().info('Available tools: memory_store, memory_find, system_status');
  } catch (error) {
    console.error('❌ Failed to start Cortex Memory MCP Server:', error);
    process.exit(1);
  }
}

// Start the server if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error('❌ Server startup failed:', error);
    process.exit(1);
  });
}

// Export the factory for external use
export { createMcpServer };
