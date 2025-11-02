#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

console.error('=== Starting Minimal MCP Test ===');
console.error('MCP SDK loaded successfully');

try {
  const server = new Server(
    { name: 'test-mcp', version: '1.0.0' },
    { capabilities: { tools: {} } }
  );

  console.error('MCP Server created');

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    console.error('Tools list requested');
    return {
      tools: [
        {
          name: 'test',
          description: 'Test tool',
          inputSchema: { type: 'object', properties: {} },
        },
      ],
    };
  });

  console.error('Tool handlers registered');

  const transport = new StdioServerTransport();
  console.error('Transport created');

  server
    .connect(transport)
    .then(() => {
      console.error('MCP Server connected and ready!');
    })
    .catch((error) => {
      console.error('Failed to connect:', error.message);
      process.exit(1);
    });
} catch (error) {
  console.error('Error:', error.message);
  console.error('Stack:', error.stack);
  process.exit(1);
}
