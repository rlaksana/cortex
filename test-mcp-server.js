#!/usr/bin/env node
/**
 * Test MCP server with high-level API
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

// Simple test server using high-level API
const server = new McpServer({
  name: 'test-mcp-server',
  version: '1.0.0'
});

// Register memory_store tool (simplified version)
server.registerTool(
  'memory_store',
  {
    title: 'Memory Store',
    description: 'Store knowledge items in Cortex memory with advanced deduplication, TTL, truncation, and insights.',
    inputSchema: {
      type: 'object',
      properties: {
        items: {
          type: 'array',
          description: 'Knowledge items to store',
          items: {
            type: 'object',
            properties: {
              kind: { type: 'string', description: 'Knowledge type' },
              data: { type: 'object', description: 'Knowledge data' }
            },
            required: ['kind', 'data']
          }
        }
      },
      required: ['items']
    }
  },
  async (args) => {
    return {
      content: [{ type: 'text', text: `Memory store called with ${args.items?.length || 0} items` }]
    };
  }
);

// Register memory_find tool (simplified version)
server.registerTool(
  'memory_find',
  {
    title: 'Memory Find',
    description: 'Search Cortex memory with advanced strategies and graph expansion.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search query' },
        limit: { type: 'number', description: 'Result limit', default: 10 }
      },
      required: ['query']
    }
  },
  async (args) => {
    return {
      content: [{ type: 'text', text: `Memory find called with query: ${args.query}` }]
    };
  }
);

// Register system_status tool (simplified version)
server.registerTool(
  'system_status',
  {
    title: 'System Status',
    description: 'System monitoring, cleanup, and maintenance operations.',
    inputSchema: {
      type: 'object',
      properties: {
        operation: {
          type: 'string',
          enum: ['status', 'health_check', 'cleanup'],
          description: 'Operation to perform',
          default: 'status'
        }
      },
      required: []
    }
  },
  async (args) => {
    return {
      content: [{ type: 'text', text: `System status called with operation: ${args.operation || 'status'}` }]
    };
  }
);

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('[INFO] Test MCP server started with high-level API');
}

main().catch(console.error);