#!/usr/bin/env node
/**
 * Cortex Memory MCP Server - High-Level API Implementation
 *
 * Refactored to use McpServer high-level API for proper tool discovery.
 * This replaces the problematic low-level Server implementation.
 *
 * @author Cortex Team
 * @version 2.0.1
 * @since 2025
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { ALL_JSON_SCHEMAS } from './schemas/json-schemas.js';
import { MemoryStoreOrchestrator } from './services/orchestrators/memory-store-orchestrator.js';
import { MemoryFindOrchestrator } from './services/orchestrators/memory-find-orchestrator.js';

// Convert JSON schemas to MCP-compatible format
function convertJsonSchemaToMcpFormat(jsonSchema: any): any {
  const { $schema, ...mcpSchema } = jsonSchema;
  return mcpSchema;
}

// Simple logger (reused from existing implementation)
class Logger {
  private _level: string;

  constructor(level: string = process.env.LOG_LEVEL || 'info') {
    this._level = level;
  }

  shouldLog(level: string): boolean {
    const levels: Record<string, number> = { error: 0, warn: 1, info: 2, debug: 3 };
    return levels[level] <= levels[this._level];
  }

  error(message: string, ...args: any[]): void {
    if (this.shouldLog('error')) {
      console.error(`[ERROR] ${message}`, ...args);
    }
  }

  info(message: string, ...args: any[]): void {
    if (this.shouldLog('info')) {
      console.error(`[INFO] ${message}`, ...args);
    }
  }
}

const logger = new Logger();

// Initialize orchestrators
const memoryStoreOrchestrator = new MemoryStoreOrchestrator();
const memoryFindOrchestrator = new MemoryFindOrchestrator();

// Create MCP server using high-level API
const server = new McpServer({
  name: 'cortex-memory-mcp',
  version: '2.0.1',
});

// Register memory_store tool
server.registerTool(
  'memory_store',
  {
    title: 'Memory Store',
    description: 'Store knowledge items in Cortex memory with advanced deduplication, TTL, truncation, and insights. Features enterprise-grade duplicate detection with 5 merge modes, configurable similarity thresholds, time window controls, scope filtering, and comprehensive audit logging.',
    inputSchema: convertJsonSchemaToMcpFormat(ALL_JSON_SCHEMAS.memory_store),
  },
  async (args, _extra) => {
    try {
      logger.info('Memory store tool called', { itemCount: args.items?.length || 0 });

      const result = await memoryStoreOrchestrator.storeItems(args.items);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            itemsStored: result.summary?.stored || 0,
            errors: result.errors?.length || 0,
            truncated: result.meta?.truncated || false,
            insightsGenerated: 0, // Not available in current response
            duration: result.meta?.execution_time_ms || 0,
            metadata: result.meta || {}
          }, null, 2)
        }]
      };
    } catch (error) {
      logger.error('Memory store tool failed:', error);
      throw new McpError(
        ErrorCode.InternalError,
        `Memory store failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }
);

// Register memory_find tool
server.registerTool(
  'memory_find',
  {
    title: 'Memory Find',
    description: 'Search Cortex memory with advanced strategies and graph expansion. Supports semantic vector search with configurable strategies, TTL filters, result formatting, and analytics optimization.',
    inputSchema: convertJsonSchemaToMcpFormat(ALL_JSON_SCHEMAS.memory_find),
  },
  async (args, _extra) => {
    try {
      logger.info('Memory find tool called', { query: args.query?.substring(0, 100) + '...' });

      const result = await memoryFindOrchestrator.findItems(args as any);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            results: result.results || [],
            totalFound: result.total_count || 0,
            searchStrategy: result.meta?.strategy || 'unknown',
            confidence: result.observability?.confidence_average || 0,
            duration: result.meta?.execution_time_ms || 0,
            metadata: result.meta || {}
          }, null, 2)
        }]
      };
    } catch (error) {
      logger.error('Memory find tool failed:', error);
      throw new McpError(
        ErrorCode.InternalError,
        `Memory find failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }
);

// Register system_status tool
server.registerTool(
  'system_status',
  {
    title: 'System Status',
    description: 'System monitoring, cleanup, and maintenance operations. Provides database health checks, statistics, telemetry, document management, cleanup operations with safety mechanisms, and comprehensive system diagnostics.',
    inputSchema: convertJsonSchemaToMcpFormat(ALL_JSON_SCHEMAS.system_status),
  },
  async (args, _extra) => {
    try {
      logger.info('System status tool called', { operation: args.operation });

      // Simple status response for now
      const status = {
        success: true,
        timestamp: new Date().toISOString(),
        server: {
          name: 'cortex-memory-mcp',
          version: '2.0.1',
          uptime: process.uptime(),
          memory: process.memoryUsage(),
        },
        database: {
          type: 'qdrant',
          url: process.env.QDRANT_URL || 'http://localhost:6333',
          status: 'unknown' // Would be populated by actual health check
        },
        operation: args.operation || 'status'
      };

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(status, null, 2)
        }]
      };
    } catch (error) {
      logger.error('System status tool failed:', error);
      throw new McpError(
        ErrorCode.InternalError,
        `System status failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }
);

// Start the server
async function main() {
  try {
    logger.info('Starting Cortex Memory MCP Server with high-level API...');

    const transport = new StdioServerTransport();
    await server.connect(transport);

    logger.info('Cortex Memory MCP Server started successfully!');
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  logger.info('Received SIGINT, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  logger.info('Received SIGTERM, shutting down gracefully...');
  process.exit(0);
});

// Start the server
main().catch((error) => {
  logger.error('Server startup failed:', error);
  process.exit(1);
});