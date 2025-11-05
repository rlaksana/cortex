#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';

// Simple stub server that defers complex initialization
const server = new Server({ name: 'cortex', version: '1.0.0' }, { capabilities: { tools: {} } });

// Basic auth service stub
const authService = {
  verifyAccessToken: (token) => {
    if (token === 'test-token') {
      return { jti: 'test-session-id', session_id: 'test-session-id' };
    }
    throw new Error('Invalid token');
  },
  generateAccessToken: () => 'test-access-token',
  generateRefreshToken: () => 'test-refresh-token',
  refreshToken: () => ({
    access_token: 'new-access-token',
    refresh_token: 'new-refresh-token',
    token_type: 'Bearer',
    expires_in: 900,
  }),
  revokeToken: () => {},
  revokeSession: () => {},
  createSession: () => ({ id: 'session-id' }),
  getUserScopes: () => ['memory:read', 'memory:write', 'search:basic'],
};

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'memory_store',
      description: 'Store knowledge items (simplified version)',
      inputSchema: {
        type: 'object',
        properties: {
          items: {
            type: 'array',
            items: { type: 'object' },
          },
          auth_token: {
            type: 'string',
            description: 'Authentication token (use "test-token")',
          },
        },
        required: ['items', 'auth_token'],
      },
    },
    {
      name: 'memory_find',
      description: 'Find knowledge items (simplified version)',
      inputSchema: {
        type: 'object',
        properties: {
          query: { type: 'string' },
          auth_token: {
            type: 'string',
            description: 'Authentication token (use "test-token")',
          },
        },
        required: ['query', 'auth_token'],
      },
    },
    {
      name: 'auth_login',
      description: 'Authenticate (use admin/admin123)',
      inputSchema: {
        type: 'object',
        properties: {
          username: { type: 'string' },
          password: { type: 'string' },
        },
        required: ['username', 'password'],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'memory_store': {
        const { items, auth_token } = args;
        if (!auth_token) {
          throw new Error('Authentication token required');
        }

        // Simple token validation
        try {
          authService.verifyAccessToken(auth_token);
        } catch {
          throw new Error('Invalid authentication token');
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  items: items,
                  stored_count: items.length,
                  message: 'Memory items stored successfully (simplified version)',
                  timestamp: new Date().toISOString(),
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case 'memory_find': {
        const { query, auth_token } = args;
        if (!auth_token) {
          throw new Error('Authentication token required');
        }

        try {
          authService.verifyAccessToken(auth_token);
        } catch {
          throw new Error('Invalid authentication token');
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  query: query,
                  hits: [],
                  message: 'Search completed (simplified version)',
                  timestamp: new Date().toISOString(),
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case 'auth_login': {
        const { username, password } = args;

        if (username === 'admin' && password === 'admin123') {
          const mockUser = {
            id: 'admin-user-id',
            username: 'admin',
            role: 'admin',
          };

          const session = authService.createSession(mockUser, 'mcp-client', 'mcp-client');
          const scopes = authService.getUserScopes(mockUser);
          const accessToken = authService.generateAccessToken(mockUser, session.id, scopes);
          const refreshToken = authService.generateRefreshToken(mockUser, session.id);

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    access_token: accessToken,
                    refresh_token: refreshToken,
                    token_type: 'Bearer',
                    expires_in: 900,
                    scope: scopes,
                    user: {
                      id: mockUser.id,
                      username: mockUser.username,
                      role: mockUser.role,
                    },
                    message: 'Authentication successful (simplified version)',
                  },
                  null,
                  2
                ),
              },
            ],
          };
        } else {
          throw new Error('Invalid username or password');
        }
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            {
              error: error instanceof Error ? error.message : String(error),
              timestamp: new Date().toISOString(),
            },
            null,
            2
          ),
        },
      ],
      isError: true,
    };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Cortex MCP Server (Simplified Version) started');
}

main().catch((error) => {
  console.error('Server failed to start:', error);
  process.exit(1);
});
