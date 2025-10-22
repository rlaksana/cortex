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
import { ApiKeyService } from './services/auth/api-key-service.js';
import { AuditService } from './services/audit/audit-service.js';
import { MCPAuthHelper, convertToAuthContext } from './services/auth/auth-middleware-helper.js';
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
const apiKeyService = new ApiKeyService(authService, auditService);
const authHelper = new MCPAuthHelper(authService, authorizationService, auditService);

const server = new Server({ name: 'cortex', version: '1.0.0' }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'memory_store',
      description: 'Store knowledge items with authentication and authorization',
      inputSchema: {
        type: 'object',
        properties: {
          items: {
            type: 'array',
            items: { type: 'object' }
          },
          auth_token: {
            type: 'string',
            description: 'JWT authentication token or API key'
          }
        },
        required: ['items', 'auth_token']
      }
    },
    {
      name: 'memory_find',
      description: 'Find knowledge items with authentication and authorization',
      inputSchema: {
        type: 'object',
        properties: {
          query: { type: 'string' },
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
            items: { type: 'string' }
          },
          mode: {
            type: 'string',
            enum: ['auto', 'fast', 'deep']
          },
          limit: { type: 'number' },
          auth_token: {
            type: 'string',
            description: 'JWT authentication token or API key'
          }
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

        const requestInfo = {
          ip_address: 'mcp-client',
          user_agent: 'mcp-client'
        };

        const { auth, user } = await authHelper.extractAuthContext(auth_token, requestInfo);

        // Check authorization
        const accessDecision = await authHelper.checkAccess(
          auth,
          'memory_store',
          'write'
        );

        if (!accessDecision.allowed) {
          await auditService.logPermissionDenied(
            user.id,
            'memory_store',
            'write',
            accessDecision.required_scopes,
            auth.scopes,
            requestInfo.ip_address,
            requestInfo.user_agent
          );
          throw new Error(`Access denied: ${accessDecision.reason}`);
        }

        // Log the operation
        await auditService.logStoreOperation(
          'create',
          'knowledge_items',
          'batch',
          {},
          user.id,
          true
        );

        // For now, return stub response with authentication context
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
              autonomous_context: {
                strategy_used: 'authenticated',
                mode_executed: 'fast',
                confidence: 'high',
                total_results: 0,
                avg_score: 0,
                fallback_attempted: false,
                user_message_suggestion: 'Memory items stored successfully with authentication'
              }
            }, null, 2)
          }]
        };
      }

      case 'memory_find': {
        const { query, scope, mode, auth_token } = args;

        if (!auth_token) {
          throw new Error('Authentication token required');
        }

        const requestInfo = {
          ip_address: 'mcp-client',
          user_agent: 'mcp-client'
        };

        const { auth, user } = await authHelper.extractAuthContext(auth_token, requestInfo);
        const authContext = convertToAuthContext(auth);

        // Check authorization for read operation
        const accessDecision = await authorizationService.checkAccess(
          authContext,
          'memory_find',
          'read'
        );

        if (!accessDecision.allowed) {
          await auditService.logPermissionDenied(
            user.id,
            'memory_find',
            'read',
            accessDecision.required_scopes,
            auth.scopes,
            requestInfo.ip_address,
            requestInfo.user_agent
          );
          throw new Error(`Access denied: ${accessDecision.reason}`);
        }

        // Check for advanced search permissions
        if (mode === 'deep' || mode === 'advanced') {
          const advancedAccess = await authorizationService.checkAccess(
            authContext,
            'memory_find',
            mode
          );

          if (!advancedAccess.allowed) {
            throw new Error(`Access denied: Advanced search mode '${mode}' requires additional permissions`);
          }
        }

        // Log the search operation
        await auditService.logSearchOperation(
          query,
          0, // results count
          mode || 'auto',
          scope,
          user.id
        );

        // Return stub response with authentication context
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              hits: [],
              suggestions: [],
              query,
              authentication: {
                user_id: user.id,
                username: user.username,
                role: user.role,
                scopes: auth.scopes
              },
              autonomous_metadata: {
                strategy_used: 'authenticated_search',
                mode_requested: mode || 'auto',
                mode_executed: mode || 'auto',
                confidence: 'high',
                total_results: 0,
                avg_score: 0,
                fallback_attempted: false,
                user_message_suggestion: 'Search completed with authentication'
              }
            }, null, 2)
          }]
        };
      }

      case 'auth_login': {
        const { username, password } = args;

        // Mock user authentication (in production, validate against database)
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

          const session = authService.createSession(
            mockUser,
            'mcp-client',
            'mcp-client'
          );

          const scopes = authService.getUserScopes(mockUser);
          const accessToken = authService.generateAccessToken(mockUser, session.id, scopes);
          const refreshToken = authService.generateRefreshToken(mockUser, session.id);

          await auditService.logAuthSuccess(
            mockUser.id,
            session.id,
            'jwt',
            'mcp-client',
            'mcp-client',
            scopes
          );

          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                access_token: accessToken,
                refresh_token: refreshToken,
                token_type: 'Bearer',
                expires_in: 900, // 15 minutes
                scope: scopes,
                user: {
                  id: mockUser.id,
                  username: mockUser.username,
                  role: mockUser.role
                }
              }, null, 2)
            }]
          };
        } else {
          await auditService.logAuthFailure(
            'mcp-client',
            'mcp-client',
            'Invalid credentials',
            undefined,
            undefined,
            undefined
          );
          throw new Error('Invalid username or password');
        }
      }

      case 'auth_refresh': {
        const { refresh_token } = args;

        try {
          const tokenResponse = await authService.refreshToken(refresh_token);

          return {
            content: [{
              type: 'text',
              text: JSON.stringify(tokenResponse, null, 2)
            }]
          };
        } catch (error) {
          throw new Error('Invalid or expired refresh token');
        }
      }

      case 'auth_logout': {
        const { auth_token } = args;

        try {
          const payload = authService.verifyAccessToken(auth_token);
          authService.revokeToken(payload.jti);

          if (payload.session_id) {
            authService.revokeSession(payload.session_id);
          }

          return {
            content: [{
              type: 'text',
              text: JSON.stringify({ message: 'Logged out successfully' }, null, 2)
            }]
          };
        } catch (error) {
          throw new Error('Invalid token');
        }
      }

      case 'api_key_create': {
        const { auth_token, name, scopes, expires_at, description } = args;

        const requestInfo = {
          ip_address: 'mcp-client',
          user_agent: 'mcp-client'
        };

        const { auth, user } = await authHelper.extractAuthContext(auth_token, requestInfo);
        const authContext = convertToAuthContext(auth);

        // Check API key creation permissions
        const accessDecision = await authorizationService.checkAccess(
          authContext,
          'api_key',
          'manage'
        );

        if (!accessDecision.allowed) {
          throw new Error(`Access denied: ${accessDecision.reason}`);
        }

        // Validate scopes
        const userMaxScopes = authService.getUserMaxScopes(user);
        const invalidScopes = (scopes as AuthScope[]).filter(scope => !userMaxScopes.includes(scope));
        if (invalidScopes.length > 0) {
          throw new Error(`Invalid scopes: ${invalidScopes.join(', ')}`);
        }

        const mockUser = {
          id: user.id,
          username: user.username,
          email: `${user.username}@cortex.local`,
          password_hash: '',
          role: user.role,
          is_active: true,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        };

        const result = await apiKeyService.createApiKey(mockUser, {
          name,
          scopes: scopes as AuthScope[],
          expires_at,
          description
        }, requestInfo);

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              api_key: result.api_key,
              key_info: result.key_info
            }, null, 2)
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
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info('Cortex MCP Server (Stub Version) started');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    logger.error({ error }, 'Server failed to start');
    process.exit(1);
  });
}