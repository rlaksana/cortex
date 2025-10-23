#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';

// Simple in-memory token store for the simplified version
class TokenStore {
  private static validTokens = new Set<string>([
    'test-token',
    'test-access-token',
    'test-refresh-token'
  ]);

  static addToken(token: string) {
    this.validTokens.add(token);
  }

  static isValid(token: string): boolean {
    return this.validTokens.has(token);
  }

  static removeToken(token: string) {
    this.validTokens.delete(token);
  }

  static clearAll() {
    this.validTokens.clear();
    this.validTokens.add('test-token');
    this.validTokens.add('test-access-token');
    this.validTokens.add('test-refresh-token');
  }
}

// Simple stub server that defers complex initialization
const server = new Server(
  { name: 'cortex', version: '1.0.0' },
  { capabilities: { tools: {} } }
);

// Basic auth service stub
const authService = {
  verifyAccessToken: (token) => {
    if (TokenStore.isValid(token)) {
      return { jti: 'test-session-id', session_id: 'test-session-id' };
    }
    throw new Error('Invalid token');
  },
  generateAccessToken: (user, sessionId, scopes) => {
    const token = 'test-access-token';
    TokenStore.addToken(token);
    return token;
  },
  generateRefreshToken: (user, sessionId) => {
    const token = 'test-refresh-token';
    TokenStore.addToken(token);
    return token;
  },
  refreshToken: (refreshToken) => {
    // Generate unique tokens with timestamp to avoid conflicts
    const timestamp = Date.now();
    const newAccessToken = `new-access-token-${timestamp}`;
    const newRefreshToken = `new-refresh-token-${timestamp}`;

    // Add the new tokens to our token store
    TokenStore.addToken(newAccessToken);
    TokenStore.addToken(newRefreshToken);

    return {
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
      token_type: 'Bearer',
      expires_in: 900
    };
  },
  revokeToken: (tokenId) => {
    TokenStore.removeToken(tokenId);
  },
  revokeSession: (sessionId) => {
    // In a real implementation, we'd find and remove all tokens for this session
    // For this simplified version, we'll clear everything except the default
    TokenStore.clearAll();
  },
  createSession: (user, ip, userAgent) => ({ id: 'session-id' }),
  getUserScopes: (user) => ['memory:read', 'memory:write', 'search:basic']
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
            items: { type: 'object' }
          },
          auth_token: {
            type: 'string',
            description: 'Authentication token (use "test-token")'
          }
        },
        required: ['items', 'auth_token']
      }
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
            description: 'Authentication token (use "test-token")'
          }
        },
        required: ['query', 'auth_token']
      }
    },
    {
      name: 'auth_login',
      description: 'Authenticate (use admin/admin123)',
      inputSchema: {
        type: 'object',
        properties: {
          username: { type: 'string' },
          password: { type: 'string' }
        },
        required: ['username', 'password']
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
        try {
          authService.verifyAccessToken(auth_token);
        } catch {
          throw new Error('Invalid authentication token');
        }

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              items,
              stored_count: items.length,
              message: 'Memory items stored successfully (simplified version)',
              timestamp: new Date().toISOString()
            }, null, 2)
          }]
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
          content: [{
            type: 'text',
            text: JSON.stringify({
              query,
              hits: [],
              message: 'Search completed (simplified version)',
              timestamp: new Date().toISOString()
            }, null, 2)
          }]
        };
      }

      case 'auth_login': {
        const { username, password } = args;

        if (username === 'admin' && password === 'admin123') {
          const mockUser = {
            id: 'admin-user-id',
            username: 'admin',
            role: 'admin'
          };

          const session = authService.createSession(mockUser, 'mcp-client', 'mcp-client');
          const scopes = authService.getUserScopes(mockUser);
          const accessToken = authService.generateAccessToken(mockUser, session.id, scopes);
          const refreshToken = authService.generateRefreshToken(mockUser, session.id);

          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                access_token: accessToken,
                refresh_token: refreshToken,
                token_type: 'Bearer',
                expires_in: 900,
                scope: scopes,
                user: {
                  id: mockUser.id,
                  username: mockUser.username,
                  role: mockUser.role
                },
                message: 'Authentication successful (simplified version)'
              }, null, 2)
            }]
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
  console.error('Cortex MCP Server (Simplified Version) started');
}

main().catch((error) => {
  console.error('Server failed to start:', error);
  process.exit(1);
});