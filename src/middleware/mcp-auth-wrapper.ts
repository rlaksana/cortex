// @ts-nocheck - Emergency rollback: Critical middleware service
/**
 * MCP Authentication Wrapper
 *
 * Provides wrapper functions for MCP tool handlers that enforce
 * API key scopes before executing the actual tool logic
 */

import { logger } from '@/utils/logger.js';

import { validateToolScope } from './scope-middleware.js';
import type { AuthContext } from '../types/auth-types.js';

/**
 * Configuration for MCP tool authentication
 */
interface MCPToolConfig {
  toolName: string;
  requireAuth: boolean;
  defaultMode?: string;
  auditLogging?: boolean;
}

/**
 * Error thrown when authentication fails
 */
export class MCPAuthenticationError extends Error {
  constructor(
    message: string,
    public _toolName: string,
    public _authContext?: AuthContext
  ) {
    super(message);
    this.name = 'MCPAuthenticationError';
  }
}

/**
 * Wrapper that enforces authentication and scopes before executing MCP tools
 */
export class MCPAuthWrapper {
  private static instance: MCPAuthWrapper;

  private constructor() {}

  public static getInstance(): MCPAuthWrapper {
    if (!MCPAuthWrapper.instance) {
      MCPAuthWrapper.instance = new MCPAuthWrapper();
    }
    return MCPAuthWrapper.instance;
  }

  /**
   * Wrap an MCP tool handler with authentication and scope validation
   */
  async wrapToolHandler<T extends Record<string, unknown>, R>(
    config: MCPToolConfig,
    handler: (args: T, authContext: AuthContext) => Promise<R>,
    args: T & { auth_token?: string }
  ): Promise<R> {
    const startTime = Date.now();
    const { toolName, requireAuth } = config;

    try {
      // Check if authentication is required
      if (requireAuth && !args.auth_token) {
        throw new MCPAuthenticationError(`Authentication token required for ${toolName}`, toolName);
      }

      // Validate token and scopes if authentication is required
      let authContext: AuthContext | undefined;
      if (requireAuth && args.auth_token) {
        authContext = await validateToolScope(args.auth_token, toolName, args);

        logger.info(
          {
            toolName,
            userId: authContext.user.id,
            username: authContext.user.username,
            role: authContext.user.role,
            args: this.sanitizeArgs(args),
          },
          `Authenticated ${toolName} request`
        );
      }

      // Execute the actual handler
      const result = await handler(args as T, authContext!);

      // Log successful execution
      if (config.auditLogging !== false) {
        logger.info(
          {
            toolName,
            userId: authContext?.user.id,
            executionTime: Date.now() - startTime,
            success: true,
          },
          `${toolName} completed successfully`
        );
      }

      return result;
    } catch (error) {
      const executionTime = Date.now() - startTime;

      // Handle authentication errors specifically
      if (error instanceof MCPAuthenticationError) {
        logger.warn(
          {
            toolName,
            error: error.message,
            userId: error._authContext?.user.id,
            executionTime,
          },
          `Authentication failed for ${toolName}`
        );

        throw error;
      }

      // Handle scope errors - use undefined since we don't have authContext in this catch block
      if (error instanceof Error && error.message.includes('Insufficient permissions')) {
        logger.warn(
          {
            toolName,
            error: error.message,
            executionTime,
          },
          `Scope validation failed for ${toolName}`
        );

        throw new MCPAuthenticationError(
          `Insufficient permissions for ${toolName}: ${error.message}`,
          toolName
        );
      }

      // Log other errors
      logger.error(
        {
          toolName,
          error: error instanceof Error ? error.message : String(error),
          executionTime,
          args: this.sanitizeArgs(args),
        },
        `${toolName} failed`
      );

      throw error;
    }
  }

  /**
   * Create a wrapped memory_find handler
   */
  createMemoryFindHandler(
    _originalHandler: (args: unknown, _authContext?: AuthContext) => Promise<unknown>
  ) {
    return async (args: unknown) => {
      return this.wrapToolHandler(
        {
          toolName: 'memory_find',
          requireAuth: true,
          auditLogging: true,
        },
        _originalHandler,
        args
      );
    };
  }

  /**
   * Create a wrapped memory_store handler
   */
  createMemoryStoreHandler(
    _originalHandler: (args: unknown, _authContext?: AuthContext) => Promise<unknown>
  ) {
    return async (args: unknown) => {
      return this.wrapToolHandler(
        {
          toolName: 'memory_store',
          requireAuth: true,
          auditLogging: true,
        },
        _originalHandler,
        args
      );
    };
  }

  /**
   * Create a wrapped database_health handler
   */
  createDatabaseHealthHandler(
    _originalHandler: (args: unknown, _authContext?: AuthContext) => Promise<unknown>
  ) {
    return async (args: unknown) => {
      return this.wrapToolHandler(
        {
          toolName: 'database_health',
          requireAuth: true,
          auditLogging: false, // Health checks are less sensitive
        },
        _originalHandler,
        args
      );
    };
  }

  /**
   * Create a wrapped database_stats handler
   */
  createDatabaseStatsHandler(
    _originalHandler: (args: unknown, _authContext?: AuthContext) => Promise<unknown>
  ) {
    return async (args: unknown) => {
      return this.wrapToolHandler(
        {
          toolName: 'database_stats',
          requireAuth: true,
          auditLogging: false,
        },
        _originalHandler,
        args
      );
    };
  }

  /**
   * Sanitize arguments for logging (remove sensitive data)
   */
  private sanitizeArgs(args: Record<string, unknown>): Record<string, unknown> {
    const sanitized = { ...args };

    // Remove sensitive fields
    delete sanitized.auth_token;
    delete sanitized.password;
    delete sanitized.api_key;
    delete sanitized.secret;

    // Truncate long strings
    Object.keys(sanitized).forEach((key) => {
      if (typeof sanitized[key] === 'string' && sanitized[key].length > 100) {
        sanitized[key] = `${sanitized[key].substring(0, 100)}...`;
      }
    });

    return sanitized;
  }

  /**
   * Get user information from authenticated request
   */
  getUserInfo(authContext: AuthContext): {
    id: string;
    username: string;
    role: string;
    scopes: string[];
  } {
    return {
      id: authContext.user.id,
      username: authContext.user.username,
      role: authContext.user.role,
      scopes: authContext.scopes,
    };
  }

  /**
   * Check if user has specific scope
   */
  userHasScope(authContext: AuthContext, scope: string): boolean {
    return authContext.scopes.includes(scope as unknown);
  }

  /**
   * Check if user has admin privileges
   */
  userIsAdmin(authContext: AuthContext): boolean {
    const adminScopes = [
      'user:manage',
      'api_key:manage',
      'system:manage',
      'audit:write',
      'scope:manage',
    ];

    return authContext.scopes.some((scope) => adminScopes.includes(scope));
  }
}

// Export singleton instance
export const mcpAuthWrapper = MCPAuthWrapper.getInstance();

/**
 * Higher-order function to wrap MCP tool handlers
 */
export function withAuth<T extends Record<string, unknown>, R>(
  config: MCPToolConfig,
  handler: (args: T, _authContext: AuthContext) => Promise<R>
) {
  return async (args: T & { auth_token?: string }): Promise<R> => {
    return mcpAuthWrapper.wrapToolHandler(config, handler, args);
  };
}

/**
 * Convenience functions for common tool wrapping patterns
 */
export const authenticatedHandlers = {
  memoryFind: (handler: unknown) => mcpAuthWrapper.createMemoryFindHandler(handler),
  memoryStore: (handler: unknown) => mcpAuthWrapper.createMemoryStoreHandler(handler),
  databaseHealth: (handler: unknown) => mcpAuthWrapper.createDatabaseHealthHandler(handler),
  databaseStats: (handler: unknown) => mcpAuthWrapper.createDatabaseStatsHandler(handler),
};
