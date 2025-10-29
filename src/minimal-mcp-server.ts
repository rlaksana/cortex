#!/usr/bin/env node

/**
 * Minimal MCP Server for testing - NO dotenv, NO logging to stdout
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';

// === MCP Server Setup ===

const server = new Server(
  {
    name: 'cortex-memory-mcp',
    version: '2.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// === Tool Definitions ===

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'test_tool',
        description: 'Simple test tool',
        inputSchema: {
          type: 'object',
          properties: {},
          required: [],
        },
      },
    ],
  };
});

// === Tool Handlers ===

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name } = request.params;

  if (name === 'test_tool') {
    return {
      content: [
        {
          type: 'text',
          text: 'Test tool executed successfully!',
        },
      ],
    };
  }

  throw new Error(`Unknown tool: ${name}`);
});

// === Server Startup - NO LOGGING TO STDOUT ===

async function startServer(): Promise<void> {
  try {
    // NO dotenv - we'll set env manually if needed
    // NO console.log statements

    // Create MCP transport and connect immediately
    const transport = new StdioServerTransport();
    await server.connect(transport);

    // NO success logging to stdout
  } catch (error) {
    // Only log errors to stderr
    console.error('Server startup failed:', error);
    process.exit(1);
  }
}

// Handle process termination
process.on('SIGINT', () => {
  process.exit(0);
});

process.on('SIGTERM', () => {
  process.exit(0);
});

// Start the server
startServer().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
