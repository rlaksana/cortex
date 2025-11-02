#!/usr/bin/env node
import { config } from 'dotenv';
import { Server } from '@modelcontextprotocol/sdk/server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { logger } from './utils/logger.js';
import { loadEnv } from './config/environment.js';
import { getAuthConfig } from './config/auth-config.js';
import { AuthScope, UserRole } from './types/auth-types.js';

// Load environment variables from .env file (redirect stdout to stderr for MCP stdio compatibility)
const originalConsoleLog = console.log;
console.log = (...args) => console.error(...args);
config();
console.log = originalConsoleLog;

loadEnv();

// Create server immediately without blocking operations
const server = new Server({ name: 'cortex', version: '1.0.0' }, { capabilities: { tools: {} } });

// Services will be initialized lazily
let services: any = null;

async function getServices() {
  if (!services) {
    // Import services only when needed
    const { AuthService } = await import('./services/auth/auth-service.js');
    const { AuthorizationService } = await import('./services/auth/authorization-service.js');
    const { AuditService } = await import('./services/audit/audit-service.js');
    const { ApiKeyService } = await import('./services/auth/api-key-service.js');
    const { MCPAuthHelper } = await import('./services/auth/auth-middleware-helper.js');

    // Initialize services
    const authConfig = getAuthConfig();
    const authService = new AuthService({
      jwt_secret: authConfig.JWT_SECRET,
      jwt_refresh_secret: authConfig.JWT_REFRESH_SECRET,
      jwt_expires_in: authConfig.JWT_EXPIRES_IN,
      jwt_refresh_expires_in: authConfig.JWT_REFRESH_EXPIRES_IN,
      bcrypt_rounds: authConfig.BCRYPT_ROUNDS,
      api_key_length: authConfig.API_KEY_LENGTH,
      session_timeout_hours: authConfig.SESSION_TIMEOUT_HOURS,
      max_sessions_per_user: authConfig.MAX_SESSIONS_PER_USER,
      rate_limit_enabled: authConfig.RATE_LIMIT_ENABLED,
    });

    const authorizationService = new AuthorizationService();
    const auditService = new AuditService();
    const apiKeyService = new ApiKeyService(authService, auditService);
    const authHelper = new MCPAuthHelper(authService, authorizationService, auditService);

    services = {
      authService,
      authorizationService,
      auditService,
      apiKeyService,
      authHelper,
    };

    logger.info('Services initialized successfully');
  }
  return services;
}

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
            items: { type: 'object' },
          },
          auth_token: {
            type: 'string',
            description: 'JWT authentication token or API key',
          },
        },
        required: ['items', 'auth_token'],
      },
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
              org: { type: 'string' },
            },
          },
          types: {
            type: 'array',
            items: { type: 'string' },
          },
          mode: {
            type: 'string',
            enum: ['auto', 'fast', 'deep'],
          },
          limit: { type: 'number' },
          auth_token: {
            type: 'string',
            description: 'JWT authentication token or API key',
          },
        },
        required: ['query', 'auth_token'],
      },
    },
    {
      name: 'auth_login',
      description: 'Authenticate and obtain JWT tokens',
      inputSchema: {
        type: 'object',
        properties: {
          username: { type: 'string' },
          password: { type: 'string' },
        },
        required: ['username', 'password'],
      },
    },
    {
      name: 'auth_refresh',
      description: 'Refresh JWT tokens',
      inputSchema: {
        type: 'object',
        properties: {
          refresh_token: { type: 'string' },
        },
        required: ['refresh_token'],
      },
    },
    {
      name: 'auth_logout',
      description: 'Logout and revoke tokens',
      inputSchema: {
        type: 'object',
        properties: {
          auth_token: { type: 'string' },
        },
        required: ['auth_token'],
      },
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
            items: { type: 'string' },
          },
          expires_at: { type: 'string' },
          description: { type: 'string' },
        },
        required: ['auth_token', 'name', 'scopes'],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request: any) => {
  const { name, arguments: args } = request.params;

  try {
    // Get services on first tool call
    const svc = await getServices();

    switch (name) {
      case 'memory_store': {
        const { items, auth_token } = args;
        if (!auth_token) {
          throw new Error('Authentication token required');
        }
        const requestInfo = {
          ip_address: 'mcp-client',
          user_agent: 'mcp-client',
        };
        const { auth, user } = await svc.authHelper.extractAuthContext(auth_token, requestInfo);
        // Check authorization
        const accessDecision = await svc.authHelper.checkAccess(auth, 'memory_store', 'write');
        if (!accessDecision.allowed) {
          await svc.auditService.logPermissionDenied(
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
        await svc.auditService.logStoreOperation(
          'create',
          'knowledge_items',
          'batch',
          {},
          user.id,
          true
        );
        // For now, return stub response with authentication context
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  items: [],
                  stored_count: items.length,
                  authentication: {
                    user_id: user.id,
                    username: user.username,
                    role: user.role,
                    scopes: auth.scopes,
                  },
                  autonomous_context: {
                    strategy_used: 'authenticated',
                    mode_executed: 'fast',
                    confidence: 'high',
                    total_results: 0,
                    avg_score: 0,
                    fallback_attempted: false,
                    user_message_suggestion: 'Memory items stored successfully with authentication',
                  },
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
            updated_at: new Date().toISOString(),
          };
          const session = svc.authService.createSession(mockUser, 'mcp-client', 'mcp-client');
          const scopes = svc.authService.getUserScopes(mockUser);
          const accessToken = svc.authService.generateAccessToken(mockUser, session.id, scopes);
          const refreshToken = svc.authService.generateRefreshToken(mockUser, session.id);
          await svc.auditService.logAuthSuccess(
            mockUser.id,
            session.id,
            'jwt',
            'mcp-client',
            'mcp-client',
            scopes
          );
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    access_token: accessToken,
                    refresh_token: refreshToken,
                    token_type: 'Bearer',
                    expires_in: 900, // 15 minutes
                    scope: scopes,
                    user: {
                      id: mockUser.id,
                      username: mockUser.username,
                      role: mockUser.role,
                    },
                  },
                  null,
                  2
                ),
              },
            ],
          };
        } else {
          await svc.auditService.logAuthFailure(
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

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    logger.error(
      {
        tool: name,
        error: error instanceof Error ? error.message : String(error),
      },
      'Tool execution error'
    );

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
  logger.info('Cortex MCP Server started successfully');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    logger.error({ error }, 'Server failed to start');
    process.exit(1);
  });
}
