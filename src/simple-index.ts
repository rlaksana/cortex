#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';

const server = new Server(
  { name: 'cortex', version: '1.0.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'memory_store',
      description: 'Store knowledge items with authentication',
      inputSchema: {
        type: 'object',
        properties: {
          items: {
            type: 'array',
            items: { type: 'object' }
          },
          auth_token: {
            type: 'string',
            description: 'JWT authentication token (use "test-token")'
          }
        },
        required: ['items', 'auth_token']
      }
    },
    {
      name: 'memory_find',
      description: 'Find knowledge items with authentication',
      inputSchema: {
        type: 'object',
        properties: {
          query: { type: 'string' },
          auth_token: {
            type: 'string',
            description: 'JWT authentication token (use "test-token")'
          }
        },
        required: ['query', 'auth_token']
      }
    },
    {
      name: 'auth_login',
      description: 'Authenticate with admin credentials',
      inputSchema: {
        type: 'object',
        properties: {
          username: { type: 'string' },
          password: { type: 'string' }
        },
        required: ['username', 'password']
      }
    },
    {
      name: 'auth_refresh',
      description: 'Refresh JWT tokens',
      inputSchema: {
        type: 'object',
        properties: {
          refresh_token: { type: 'string' }
        },
        required: ['refresh_token']
      }
    },
    {
      name: 'auth_logout',
      description: 'Logout and revoke tokens',
      inputSchema: {
        type: 'object',
        properties: {
          auth_token: { type: 'string' }
        },
        required: ['auth_token']
      }
    },
    {
      name: 'api_key_create',
      description: 'Create a new API key',
      inputSchema: {
        type: 'object',
        properties: {
          auth_token: { type: 'string' },
          name: { type: 'string' },
          scopes: {
            type: 'array',
            items: { type: 'string' }
          },
          expires_at: { type: 'string' },
          description: { type: 'string' }
        },
        required: ['auth_token', 'name', 'scopes']
      }
    }
  ]
}));

server.setRequestHandler(CallToolRequestSchema, async (request: any) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'memory_store': {
        const { items, auth_token } = args;
        if (!auth_token) {
          throw new Error('Authentication token required');
        }

        // Simple token validation
        if (auth_token !== 'test-token') {
          throw new Error('Invalid authentication token');
        }

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              items,
              stored_count: items.length,
              message: 'Memory items stored successfully',
              timestamp: new Date().toISOString(),
              authentication: {
                user_id: 'test-user',
                username: 'test-user',
                role: 'user',
                scopes: ['memory:read', 'memory:write']
              }
            }, null, 2)
          }]
        };
      }

      case 'memory_find': {
        const { query, auth_token } = args;
        if (!auth_token) {
          throw new Error('Authentication token required');
        }

        if (auth_token !== 'test-token') {
          throw new Error('Invalid authentication token');
        }

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              query,
              hits: [],
              message: 'Search completed successfully',
              timestamp: new Date().toISOString(),
              authentication: {
                user_id: 'test-user',
                username: 'test-user',
                role: 'user',
                scopes: ['memory:read', 'search:basic']
              }
            }, null, 2)
          }]
        };
      }

      case 'auth_login': {
        const { username, password } = args;

        if (username === 'admin' && password === 'admin123') {
          const accessToken = `test-access-token-${  Date.now()}`;
          const refreshToken = `test-refresh-token-${  Date.now()}`;

          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                access_token: accessToken,
                refresh_token: refreshToken,
                token_type: 'Bearer',
                expires_in: 900,
                scope: ['memory:read', 'memory:write', 'search:basic', 'api_key:manage'],
                user: {
                  id: 'admin-user-id',
                  username: 'admin',
                  role: 'admin'
                },
                message: 'Authentication successful'
              }, null, 2)
            }]
          };
        } else {
          throw new Error('Invalid username or password');
        }
      }

      case 'auth_refresh': {
        const { refresh_token } = args;

        if (refresh_token && refresh_token.startsWith('test-refresh-token')) {
          const newAccessToken = `test-access-token-${  Date.now()}`;
          const newRefreshToken = `test-refresh-token-${  Date.now()}`;

          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                access_token: newAccessToken,
                refresh_token: newRefreshToken,
                token_type: 'Bearer',
                expires_in: 900
              }, null, 2)
            }]
          };
        } else {
          throw new Error('Invalid or expired refresh token');
        }
      }

      case 'auth_logout': {
        const { auth_token } = args;

        if (auth_token && auth_token.startsWith('test-access-token')) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                message: 'Logged out successfully'
              }, null, 2)
            }]
          };
        } else {
          throw new Error('Invalid token');
        }
      }

      case 'api_key_create': {
        const { auth_token, name, scopes, expires_at, description } = args;

        if (!auth_token || !auth_token.startsWith('test-access-token')) {
          throw new Error('Invalid authentication token');
        }

        const apiKey = `cortex-api-key-${  Math.random().toString(36).substring(2, 15)}`;

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              api_key: apiKey,
              key_info: {
                name,
                scopes,
                expires_at,
                description,
                created_at: new Date().toISOString()
              }
            }, null, 2)
          }]
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
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
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Cortex MCP Server started successfully');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error('Server failed to start:', error);
    process.exit(1);
  });
}