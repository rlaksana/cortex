#!/usr/bin/env node

/**
 * Simple MCP Cortex Test Entry Point
 * Minimal implementation for testing connection issues
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';

const server = new Server(
  {
    name: 'cortex-test',
    version: '2.0.1',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Define available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'test_connection',
        description: 'Test MCP Cortex connection',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'memory_store',
        description: 'Store knowledge entities in Cortex Memory',
        inputSchema: {
          type: 'object',
          properties: {
            items: {
              type: 'array',
              description: 'Array of knowledge items to store',
              items: {
                type: 'object',
                properties: {
                  kind: {
                    type: 'string',
                    enum: ['entity', 'relation', 'observation', 'section', 'runbook', 'change', 'issue', 'decision', 'todo', 'release_note', 'ddl', 'pr_context', 'incident', 'release', 'risk', 'assumption']
                  },
                  data: {
                    type: 'object',
                    description: 'The knowledge data'
                  }
                },
                required: ['kind', 'data']
              }
            }
          }
        },
      },
      {
        name: 'memory_find',
        description: 'Find knowledge entities in Cortex Memory',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query'
            },
            scope: {
              type: 'object',
              properties: {
                project: { type: 'string' },
                branch: { type: 'string' },
                org: { type: 'string' }
              }
            },
            types: {
              type: 'array',
              items: {
                type: 'string'
              }
            }
          }
        },
      }
    ],
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'test_connection':
        return {
          content: [
            {
              type: 'text',
              text: `✅ MCP Cortex Test Server Connected Successfully!\n\nTimestamp: ${new Date().toISOString()}\nServer: cortex-test v2.0.1\nStatus: Ready to accept requests\n\nAvailable Tools:\n- memory_store: Store knowledge entities\n- memory_find: Find knowledge entities\n- test_connection: Test this connection`,
            },
          ],
        };

      case 'memory_store':
        return {
          content: [
            {
              type: 'text',
              text: `📝 Memory Store (Test Mode)\n\nReceived ${args.items?.length || 0} items to store:\n${JSON.stringify(args.items, null, 2)}\n\nNote: This is a test connection. Full memory storage requires the complete Cortex server.`,
            },
          ],
        };

      case 'memory_find':
        return {
          content: [
            {
              type: 'text',
              text: `🔍 Memory Find (Test Mode)\n\nSearch Query: ${args.query || 'undefined'}\nScope: ${JSON.stringify(args.scope || {})}\nTypes: ${args.types?.join(', ') || 'all'}\n\nNote: This is a test connection. Full memory search requires the complete Cortex server with Qdrant database.`,
            },
          ],
        };

      default:
        throw new McpError(
          ErrorCode.MethodNotFound,
          `Unknown tool: ${name}`
        );
    }
  } catch (error) {
    throw new McpError(
      ErrorCode.InternalError,
      `Tool execution failed: ${error.message}`
    );
  }
});

async function main() {
  console.error('🚀 Starting MCP Cortex Test Server...');

  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error('✅ MCP Cortex Test Server is ready and accepting requests!');
}

main().catch((error) => {
  console.error('❌ Failed to start MCP Cortex Test Server:', error);
  process.exit(1);
});