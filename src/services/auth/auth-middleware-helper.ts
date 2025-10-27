/**
 * Authentication Helper Functions for MCP Server
 * Simplified middleware functionality for MCP protocol authentication
 */

import { AuthService } from './auth-service.js';
import { AuthorizationService } from './authorization-service.js';
import { AuditService } from '../audit/audit-service.js';
import { AuthContext, AuthScope, UserRole } from '../../types/auth-types.js';
import { logger } from '../../utils/logger.js';

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
      role: mcpAuth.user.role as UserRole
    },
    session: mcpAuth.session,
    scopes: mcpAuth.scopes,
    token_jti: mcpAuth.token_jti
  };
}

export class MCPAuthHelper {
  constructor(
    private authService: AuthService,
    private authorizationService: AuthorizationService,
    private auditService: AuditService
  ) {}

  /**
   * Extract authentication context from token
   */
  async extractAuthContext(
    authToken: string,
    requestInfo: MCPRequestInfo
  ): Promise<{ auth: MCPAuthContext; user: any }> {
    try {
      // Try JWT token first
      if (authToken.startsWith('eyJ')) {
        const authContext = await this.authService.createAuthContext(
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
      throw new Error(`Authentication failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Check authorization for resource access
   */
  async checkAccess(
    auth: MCPAuthContext,
    resource: string,
    action: string,
    context?: Record<string, any>
  ): Promise<{ allowed: boolean; reason: string; required_scopes: AuthScope[] }> {
    try {
      const authContext = convertToAuthContext(auth);
      const decision = await this.authorizationService.checkAccess(authContext, resource, action, context);
      return {
        allowed: decision.allowed,
        reason: decision.reason,
        required_scopes: decision.required_scopes
      };
    } catch (error) {
      return {
        allowed: false,
        reason: `Authorization check failed: ${error instanceof Error ? error.message : String(error)}`,
        required_scopes: []
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
    requestInfo: MCPRequestInfo,
    scopes: AuthScope[]
  ): Promise<void> {
    try {
      await this.auditService.logAuthSuccess(
        userId,
        sessionId,
        method,
        requestInfo.ip_address,
        requestInfo.user_agent,
        scopes.map(s => s as string)
      );
    } catch (error) {
      // Log errors but don't throw to avoid breaking authentication flow
      logger.error({ error, userId, sessionId, method }, 'Failed to log auth success');
    }
  }

  /**
   * Log authentication failure
   */
  async logAuthFailure(
    requestInfo: MCPRequestInfo,
    reason: string,
    userId?: string,
    sessionId?: string
  ): Promise<void> {
    try {
      await this.auditService.logAuthFailure(
        requestInfo.ip_address,
        requestInfo.user_agent,
        reason,
        userId,
        sessionId
      );
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
    requestInfo: MCPRequestInfo
  ): Promise<void> {
    try {
      await this.auditService.logPermissionDenied(
        userId,
        resource,
        action,
        requiredScopes.map(s => s as string),
        userScopes.map(s => s as string),
        requestInfo.ip_address,
        requestInfo.user_agent
      );
    } catch (error) {
      // Log errors but don't throw to avoid breaking authentication flow
      logger.error({ error, userId, resource, action, requiredScopes, userScopes }, 'Failed to log permission denied');
    }
  }
}