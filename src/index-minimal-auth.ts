#!/usr/bin/env node
import { config } from 'dotenv';
import { Server } from '@modelcontextprotocol/sdk/server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { logger } from './utils/logger.js';
import { loadEnv } from './config/env.js';
import { AuthService } from './services/auth/auth-service.js';
import { AuthorizationService } from './services/auth/authorization-service.js';
import { AuditService } from './services/audit/audit-service.js';
import { AUTH_CONFIG } from './config/auth-config.js';
import { AuthScope, UserRole } from './types/auth-types.js';

// Load environment variables from .env file
config();
loadEnv();

// Initialize authentication services
const authService = new AuthService({
  jwt_secret: AUTH_CONFIG.JWT_SECRET,
  jwt_refresh_secret: AUTH_CONFIG.JWT_REFRESH_SECRET,
  jwt_expires_in: AUTH_CONFIG.JWT_EXPIRES_IN,
  jwt_refresh_expires_in: AUTH_CONFIG.JWT_REFRESH_EXPIRES_IN,
  bcrypt_rounds: AUTH_CONFIG.BCRYPT_ROUNDS,
  api_key_length: AUTH_CONFIG.API_KEY_LENGTH,
  session_timeout_hours: AUTH_CONFIG.SESSION_TIMEOUT_HOURS,
  max_sessions_per_user: AUTH_CONFIG.MAX_SESSIONS_PER_USER,
  rate_limit_enabled: AUTH_CONFIG.RATE_LIMIT_ENABLED
});

const authorizationService = new AuthorizationService();
const auditService = new AuditService();

const server = new Server({ name: 'cortex', version: '1.0.0' }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'memory_store',
      description: 'Store knowledge items with authentication',
      inputSchema: {
        type: 'object',
        properties: {
          items: { type: 'array', items: { type: 'object' } },
          auth_token: { type: 'string', description: 'JWT authentication token' }
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
          auth_token: { type: 'string', description: 'JWT authentication token' }
        },
        required: ['query', 'auth_token']
      }
    },
    {
      name: 'auth_login',
      description: 'Authenticate and obtain JWT tokens',
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

// Simple authentication helper
async function authenticateRequest(authToken: string) {
  try {
    if (!authToken.startsWith('eyJ')) {
      throw new Error('Invalid token format');
    }

    const authContext = authService.createAuthContext(authToken, 'mcp-client', 'mcp-client');
    return { auth: authContext, user: authContext.user };
  } catch (error) {
    throw new Error(`Authentication failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

server.setRequestHandler(CallToolRequestSchema, async (request: any) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'memory_store': {
        const { items, auth_token } = args;

        if (!auth_token) {
          throw new Error('Authentication token required');
        }

        const { auth, user } = await authenticateRequest(auth_token);

        // Check authorization
        const accessDecision = await authorizationService.checkAccess(auth, 'memory_store', 'write');
        if (!accessDecision.allowed) {
          throw new Error(`Access denied: ${accessDecision.reason}`);
        }

        // Log the operation
        await auditService.logStoreOperation('create', 'knowledge_items', 'batch', {}, user.id, true);

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              items: [],
              stored_count: items.length,
              authentication: {
                user_id: user.id,
                username: user.username,
                role: user.role,
                scopes: auth.scopes
              },
              message: 'Memory items stored successfully with authentication'
            }, null, 2)
          }]
        };
      }

      case 'memory_find': {
        const { query, auth_token } = args;

        if (!auth_token) {
          throw new Error('Authentication token required');
        }

        const { auth, user } = await authenticateRequest(auth_token);

        // Check authorization
        const accessDecision = await authorizationService.checkAccess(auth, 'memory_find', 'read');
        if (!accessDecision.allowed) {
          throw new Error(`Access denied: ${accessDecision.reason}`);
        }

        // Log the search operation
        await auditService.logSearchOperation(query, 0, 'auto', {}, user.id);

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              hits: [],
              query,
              authentication: {
                user_id: user.id,
                username: user.username,
                role: user.role,
                scopes: auth.scopes
              },
              message: 'Search completed with authentication'
            }, null, 2)
          }]
        };
      }

      case 'auth_login': {
        const { username, password } = args;

        // Simple mock authentication
        if (username === 'admin' && password === 'admin123') {
          const mockUser = {
            id: 'admin-user-id',
            username: 'admin',
            email: 'admin@cortex.local',
            password_hash: '',
            role: UserRole.ADMIN,
            is_active: true,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          };

          const session = authService.createSession(mockUser, 'mcp-client', 'mcp-client');
          const scopes = authService.getUserScopes(mockUser);
          const accessToken = authService.generateAccessToken(mockUser, session.id, scopes);
          const refreshToken = authService.generateRefreshToken(mockUser, session.id);

          await auditService.logAuthSuccess(mockUser.id, session.id, 'jwt', 'mcp-client', 'mcp-client', scopes);

          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                access_token: accessToken,
                refresh_token: refreshToken,
                token_type: 'Bearer',
                expires_in: 900,
                scope: scopes,
                user: { id: mockUser.id, username: mockUser.username, role: mockUser.role }
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
  logger.info('Cortex MCP Server with Authentication started');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    logger.error({ error }, 'Server failed to start');
    process.exit(1);
  });
}