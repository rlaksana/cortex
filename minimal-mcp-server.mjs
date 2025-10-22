/**
 * Minimal MCP server to test logger fix without database dependencies
 */

import { Server } from '@modelcontextprotocol/sdk/server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

// Import our fixed logger
import { logger } from './dist/utils/logger.js';

console.log('=== Starting Minimal MCP Server Test ===\n');

// Create a simple MCP server
const server = new Server(
  { name: 'cortex-test', version: '1.0.0' },
  { capabilities: { tools: {} } }
);

// Define simple tools
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'test_logger',
      description: 'Test the MCP-safe logger functionality',
      inputSchema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            description: 'Message to log'
          }
        },
        required: ['message']
      }
    }
  ]
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'test_logger': {
        const { message } = args;

        // Test all log levels
        logger.info({ test: true }, `Info message: ${message}`);
        logger.debug({ test: true }, `Debug message: ${message}`);
        logger.warn({ test: true }, `Warning message: ${message}`);
        logger.error({ test: true }, `Error message: ${message}`);

        return {
          content: [{
            type: 'text',
            text: `Logger test completed! Check stderr for log messages. Message: ${message}`
          }]
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    logger.error({
      tool: name,
      error: error instanceof Error ? error.message : String(error)
    }, 'Tool execution error');

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: error instanceof Error ? error.message : String(error),
          timestamp: new Date().toISOString()
        }, null, 2)
      }],
      isError: true
    };
  }
});

async function main() {
  try {
    logger.info('Starting minimal MCP server...');
    const transport = new StdioServerTransport();
    await server.connect(transport);
    logger.info('Minimal MCP Server started successfully - ready for JSON-RPC requests');
  } catch (error) {
    logger.error({ error }, 'Failed to start minimal MCP server');
    process.exit(1);
  }
}

// Start the server
main();