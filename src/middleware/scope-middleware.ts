// @ts-nocheck - Emergency rollback: Critical middleware service
/**
 * Scope Enforcement Middleware
 *
 * Enforces API key scopes on every route with proper authorization checks
 * This is critical for production security - ensures users can only access
 * what their API keys are authorized for
 */

import { logger } from '@/utils/logger.js';

import { authService } from '../services/auth/auth-service.js';
import {
  type AuthContext,
  type AuthenticatedRequest,
  AuthScope,
  RESOURCE_SCOPE_MAPPING,
} from '../types/auth-types.js';

/**
 * Scope enforcement middleware for MCP tools
 */

/**
 * Error thrown when scope validation fails
 */
export class ScopeError extends Error {
  constructor(
    message: string,
    public requiredScopes: AuthScope[],
    public userScopes: AuthScope[],
    public resource: string,
    public action: string
  ) {
    super(message);
    this.name = 'ScopeError';
  }
}

/**
 * Middleware to enforce API key scopes on MCP tool calls
 */
export class ScopeMiddleware {
  private static instance: ScopeMiddleware;

  private constructor() {}

  public static getInstance(): ScopeMiddleware {
    if (!ScopeMiddleware.instance) {
      ScopeMiddleware.instance = new ScopeMiddleware();
    }
    return ScopeMiddleware.instance;
  }

  /**
   * Validate scopes for a resource and action
   */
  async validateScope(
    authToken: string,
    resource: string,
    action: 'read' | 'write' | 'delete' | 'manage',
    additionalContext?: Record<string, unknown>
  ): Promise<AuthContext> {
    try {
      // Authenticate the token and get auth context
      const tokenPayload = await authService.verifyAccessToken(authToken);

      // Build auth context from token payload
      const authContext: AuthContext = {
        user: {
          id: tokenPayload.sub,
          username: tokenPayload.username,
          role: tokenPayload.role,
        },
        session: {
          id: tokenPayload.session_id || 'unknown',
          ip_address: 'unknown', // Will be populated by middleware
          user_agent: 'unknown', // Will be populated by middleware
        },
        scopes: tokenPayload.scopes as AuthScope[],
        token_jti: tokenPayload.jti,
      };

      // Check if user has required scopes
      const requiredScopes = this.getRequiredScopes(resource, action);
      const hasRequiredScopes = this.checkScopes(
        authContext.scopes,
        requiredScopes,
        resource,
        action,
        additionalContext
      );

      if (!hasRequiredScopes) {
        throw new ScopeError(
          `Insufficient permissions for ${action} on ${resource}`,
          requiredScopes,
          authContext.scopes,
          resource,
          action
        );
      }

      // Log successful authorization
      logger.info(
        {
          userId: authContext.user.id,
          username: authContext.user.username,
          role: authContext.user.role,
          resource,
          action,
          scopes: authContext.scopes,
          requiredScopes,
        },
        'Scope validation passed'
      );

      return authContext;
    } catch (error) {
      if (error instanceof ScopeError) {
        logger.warn(
          {
            error: error.message,
            requiredScopes: error.requiredScopes,
            userScopes: error.userScopes,
            resource: error.resource,
            action: error.action,
            authToken: `${authToken.substring(0, 8)}...`, // Log partial token for debugging
          },
          'Scope validation failed'
        );

        throw error;
      }

      // Log authentication failure
      logger.error(
        {
          error: error instanceof Error ? error.message : String(error),
          resource,
          action,
          authToken: `${authToken.substring(0, 8)}...`,
        },
        'Authentication failed during scope validation'
      );

      throw new Error(
        `Authentication failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Get required scopes for a resource and action
   */
  private getRequiredScopes(
    resource: string,
    action: 'read' | 'write' | 'delete' | 'manage'
  ): AuthScope[] {
    // Check resource mapping first
    if (RESOURCE_SCOPE_MAPPING[resource] && RESOURCE_SCOPE_MAPPING[resource][action]) {
      return RESOURCE_SCOPE_MAPPING[resource][action];
    }

    // Default scope mappings
    const defaultMappings: Record<string, Record<string, AuthScope[]>> = {
      memory_store: {
        write: [AuthScope._MEMORY_WRITE],
        read: [AuthScope._MEMORY_READ],
        delete: [AuthScope._MEMORY_DELETE],
        manage: [AuthScope._MEMORY_WRITE, AuthScope._MEMORY_DELETE],
      },
      memory_find: {
        read: [AuthScope._MEMORY_READ, AuthScope._SEARCH_BASIC],
        advanced: [AuthScope._SEARCH_ADVANCED],
        deep: [AuthScope._SEARCH_DEEP],
        manage: [AuthScope._MEMORY_READ, AuthScope._SEARCH_ADVANCED],
      },
      database_health: {
        read: [AuthScope._SYSTEM_READ],
        manage: [AuthScope._SYSTEM_MANAGE],
      },
      database_stats: {
        read: [AuthScope._SYSTEM_READ],
        manage: [AuthScope._SYSTEM_MANAGE],
      },
      telemetry_report: {
        read: [AuthScope._SYSTEM_READ],
        manage: [AuthScope._SYSTEM_MANAGE],
      },
      system_metrics: {
        read: [AuthScope._SYSTEM_READ],
        manage: [AuthScope._SYSTEM_MANAGE],
      },
    };

    return defaultMappings[resource]?.[action] || [];
  }

  /**
   * Check if user has required scopes
   */
  private checkScopes(
    userScopes: AuthScope[],
    requiredScopes: AuthScope[],
    resource: string,
    action: string,
    additionalContext?: Record<string, unknown>
  ): boolean {
    // Special checks for specific resources
    if (resource === 'memory_find') {
      return this.checkMemoryFindScopes(userScopes, requiredScopes, action, additionalContext);
    }

    // Default scope check: user must have ANY of the required scopes (not ALL)
    return requiredScopes.some((scope) => userScopes.includes(scope));
  }

  /**
   * Special scope checking for memory_find with mode-specific requirements
   */
  private checkMemoryFindScopes(
    userScopes: AuthScope[],
    _requiredScopes: AuthScope[],
    _action: string,
    context?: Record<string, unknown>
  ): boolean {
    const mode = context?.mode || 'auto';
    const expand = context?.expand || 'none';

    // Basic read scope required for all searches
    const hasBasicRead = userScopes.some((scope) =>
      [AuthScope._MEMORY_READ, AuthScope._SEARCH_BASIC].includes(scope)
    );

    if (!hasBasicRead) {
      return false;
    }

    // Check advanced/deep search requirements
    if (mode === 'deep' && !userScopes.includes(AuthScope._SEARCH_DEEP)) {
      return false;
    }

    if (
      mode === 'auto' &&
      !userScopes.includes(AuthScope._SEARCH_ADVANCED) &&
      !userScopes.includes(AuthScope._SEARCH_DEEP)
    ) {
      // Auto mode requires at least advanced search capability
      return false;
    }

    // Fast mode only requires basic search capabilities
    // (this is handled by the hasBasicRead check above)

    // Check expansion requirements
    if (expand !== 'none' && !userScopes.includes(AuthScope._SEARCH_ADVANCED)) {
      return false;
    }

    return true;
  }

  /**
   * Create a scoped request wrapper
   */
  createAuthenticatedRequest<T extends Record<string, unknown>>(
    authToken: string,
    data: T,
    resource: string,
    action: 'read' | 'write' | 'delete' | 'manage'
  ): Promise<AuthenticatedRequest & { data: T }> {
    return this.validateScope(authToken, resource, action, data).then((authContext) => ({
      auth: authContext,
      timestamp: Date.now(),
      data,
      idempotency_key: data.idempotency_key || this.generateIdempotencyKey(),
    }));
  }

  /**
   * Generate idempotency key for requests
   */
  private generateIdempotencyKey(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Check if a scope allows write operations
   */
  isWriteScope(scope: AuthScope): boolean {
    return [
      AuthScope._MEMORY_WRITE,
      AuthScope._MEMORY_DELETE,
      AuthScope._KNOWLEDGE_WRITE,
      AuthScope._KNOWLEDGE_DELETE,
      AuthScope._USER_MANAGE,
      AuthScope._API_KEY_MANAGE,
      AuthScope._SYSTEM_MANAGE,
      AuthScope._AUDIT_WRITE,
    ].includes(scope);
  }

  /**
   * Check if a scope allows read operations
   */
  isReadScope(scope: AuthScope): boolean {
    return [
      AuthScope._MEMORY_READ,
      AuthScope._KNOWLEDGE_READ,
      AuthScope._SYSTEM_READ,
      AuthScope._AUDIT_READ,
      AuthScope._SEARCH_BASIC,
      AuthScope._SEARCH_ADVANCED,
      AuthScope._SEARCH_DEEP,
    ].includes(scope);
  }

  /**
   * Check if a scope is administrative
   */
  isAdminScope(scope: AuthScope): boolean {
    return [
      AuthScope._USER_MANAGE,
      AuthScope._API_KEY_MANAGE,
      AuthScope._SYSTEM_MANAGE,
      AuthScope._AUDIT_WRITE,
      AuthScope._SCOPE_MANAGE,
    ].includes(scope);
  }
}

// Export singleton instance
export const scopeMiddleware = ScopeMiddleware.getInstance();

/**
 * Helper function to validate scope for MCP tools
 * This is the main entry point for scope validation in the MCP server
 */
export async function validateToolScope(
  authToken: string,
  toolName: string,
  args: Record<string, unknown>
): Promise<AuthContext> {
  // Map tool names to resources and actions
  const toolMappings: Record<string, { resource: string; action: string }> = {
    memory_store: { resource: 'memory_store', action: 'write' },
    memory_find: { resource: 'memory_find', action: 'read' },
    database_health: { resource: 'database_health', action: 'read' },
    database_stats: { resource: 'database_stats', action: 'read' },
    telemetry_report: { resource: 'telemetry_report', action: 'read' },
    system_metrics: { resource: 'system_metrics', action: 'read' },
  };

  const mapping = toolMappings[toolName];
  if (!mapping) {
    throw new Error(`Unknown tool: ${toolName}`);
  }

  // Extract relevant context for scope checking
  const context = {
    mode: args.mode,
    expand: args.expand,
    types: args.types,
    limit: args.limit,
  };

  return await scopeMiddleware.validateScope(
    authToken,
    mapping.resource,
    mapping.action as 'read' | 'write' | 'delete' | 'manage',
    context
  );
}
