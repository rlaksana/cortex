/**
 * Authentication Helper Functions for MCP Server
 * Simplified middleware functionality for MCP protocol authentication
 */

import { logger } from '@/utils/logger.js';

import { type AuthService } from './auth-service.js';
import { type AuthorizationService } from './authorization-service.js';
// import { AuditService } from '../audit/audit-service.js'; // REMOVED: Service file deleted
import { type AuthContext, type AuthScope, type UserRole } from '../../types/auth-types.js';

export interface MCPAuthContext {
  user: {
    id: string;
    username: string;
    role: string; // Keep as string for MCP compatibility, will be cast to UserRole
  };
  session: {
    id: string;
    ip_address: string;
    user_agent: string;
  };
  scopes: AuthScope[];
  token_jti: string;
}

export interface MCPRequestInfo {
  ip_address: string;
  user_agent: string;
}

/**
 * Convert MCPAuthContext to AuthContext by casting string role to UserRole
 */
export function convertToAuthContext(mcpAuth: MCPAuthContext): AuthContext {
  return {
    user: {
      id: mcpAuth.user.id,
      username: mcpAuth.user.username,
      role: mcpAuth.user.role as UserRole,
    },
    session: mcpAuth.session,
    scopes: mcpAuth.scopes,
    token_jti: mcpAuth.token_jti,
  };
}

export class MCPAuthHelper {
  constructor(
    private _authService: AuthService,
    private _authorizationService: AuthorizationService
    // private _auditService: AuditService // REMOVED: Service file deleted
  ) {}

  /**
   * Extract authentication context from token
   */
  async extractAuthContext(
    authToken: string,
    requestInfo: MCPRequestInfo
  ): Promise<{ auth: MCPAuthContext; user: unknown }> {
    try {
      // Try JWT token first
      if (authToken.startsWith('eyJ')) {
        const authContext = await this._authService.createAuthContext(
          authToken,
          requestInfo.ip_address,
          requestInfo.user_agent
        );
        return { auth: authContext as MCPAuthContext, user: authContext.user };
      }
      // Try API key
      else if (authToken.startsWith('ck_')) {
        // For now, implement basic API key validation
        throw new Error('API key authentication not yet implemented in MCP context');
      }

      throw new Error('Invalid authentication token format');
    } catch (error) {
      throw new Error(
        `Authentication failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Check authorization for resource access
   */
  async checkAccess(
    auth: MCPAuthContext,
    resource: string,
    action: string,
    context?: Record<string, unknown>
  ): Promise<{ allowed: boolean; reason: string; required_scopes: AuthScope[] }> {
    try {
      const authContext = convertToAuthContext(auth);
      const decision = await this._authorizationService.checkAccess(
        authContext,
        resource,
        action,
        context
      );
      return {
        allowed: decision.allowed,
        reason: decision.reason,
        required_scopes: decision.required_scopes,
      };
    } catch (error) {
      return {
        allowed: false,
        reason: `Authorization check failed: ${error instanceof Error ? error.message : String(error)}`,
        required_scopes: [],
      };
    }
  }

  /**
   * Log authentication success
   */
  async logAuthSuccess(
    userId: string,
    sessionId: string,
    method: 'jwt' | 'api_key',
    _requestInfo: MCPRequestInfo,
    _scopes: AuthScope[]
  ): Promise<void> {
    try {
      // await this._auditService.logAuthSuccess(
      //   userId,
      //   sessionId,
      //   method,
      //   requestInfo.ip_address,
      //   requestInfo.user_agent,
      //   scopes.map((s) => s as string)
      // ); // REMOVED: audit-service deleted
      // Logging disabled temporarily due to missing audit service
      logger.debug({ userId, sessionId, method }, 'Auth success (logging disabled)');
    } catch (error) {
      // Log errors but don't throw to avoid breaking authentication flow
      logger.error({ error, userId, sessionId, method }, 'Failed to log auth success');
    }
  }

  /**
   * Log authentication failure
   */
  async logAuthFailure(
    _requestInfo: MCPRequestInfo,
    reason: string,
    userId?: string,
    sessionId?: string
  ): Promise<void> {
    try {
      // await this._auditService.logAuthFailure(
      //   requestInfo.ip_address,
      //   requestInfo.user_agent,
      //   reason,
      //   userId,
      //   sessionId
      // ); // REMOVED: audit-service deleted
      // Logging disabled temporarily due to missing audit service
      logger.debug({ userId, sessionId, reason }, 'Auth failure (logging disabled)');
    } catch (error) {
      // Log errors but don't throw to avoid breaking authentication flow
      logger.error({ error, userId, sessionId, reason }, 'Failed to log auth failure');
    }
  }

  /**
   * Log permission denied
   */
  async logPermissionDenied(
    userId: string,
    resource: string,
    action: string,
    requiredScopes: AuthScope[],
    userScopes: AuthScope[],
    _requestInfo: MCPRequestInfo
  ): Promise<void> {
    try {
      // await this._auditService.logPermissionDenied(
      //   userId,
      //   resource,
      //   action,
      //   requiredScopes.map((s) => s as string),
      //   userScopes.map((s) => s as string),
      //   requestInfo.ip_address,
      //   requestInfo.user_agent
      // ); // REMOVED: audit-service deleted
      // Logging disabled temporarily due to missing audit service
      logger.debug({ userId, resource, action }, 'Permission denied (logging disabled)');
    } catch (error) {
      // Log errors but don't throw to avoid breaking authentication flow
      logger.error(
        { error, userId, resource, action, requiredScopes, userScopes },
        'Failed to log permission denied'
      );
    }
  }
}
