/**
 * Authentication Middleware for Cortex MCP
 * Provides JWT token validation, API key authentication, and scope-based authorization
 */

import { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'crypto';
import { logger } from '../utils/logger.js';
import { AuthService } from '../services/auth/auth-service.js';
import { AuditService } from '../services/audit/audit-service.js';
import {
  AuthContext,
  AuthError,
  AuthMiddlewareConfig,
  AuthScope,
  SecurityAuditLog,
  UserRole
} from '../types/auth-types.js';

export interface AuthenticatedRequest extends Request {
  auth?: AuthContext;
  user?: {
    id: string;
    username: string;
    role: UserRole;
  };
  api_key?: {
    id: string;
    name: string;
    scopes: AuthScope[];
  };
}

export class AuthMiddleware {
  constructor(
    private authService: AuthService,
    private auditService: AuditService
  ) {}

  /**
   * Main authentication middleware that handles both JWT tokens and API keys
   */
  authenticate(config: AuthMiddlewareConfig = {}) {
    return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
      const startTime = Date.now();
      const clientInfo = this.extractClientInfo(req);

      // Extract authentication token - declare outside try block for use in catch
      const authHeader = req.headers.authorization;
      const apiKeyHeader = req.headers['x-api-key'] as string;

      try {

        let authContext: AuthContext | null = null;
        let authMethod: 'jwt' | 'api_key' | null = null;

        // Try JWT authentication first
        if (authHeader && authHeader.startsWith('Bearer ')) {
          const token = authHeader.substring(7);
          authContext = await this.authenticateWithJWT(token, clientInfo);
          authMethod = 'jwt';
        }
        // Then try API key authentication
        else if (apiKeyHeader && config.allow_api_keys !== false) {
          authContext = await this.authenticateWithAPIKey(apiKeyHeader, clientInfo);
          authMethod = 'api_key';
          // API key info is stored in the auth context session
        }
        // If no authentication method found
        else {
          throw this.createAuthError('INVALID_TOKEN', 'No valid authentication credentials provided');
        }

        // Validate required scopes
        if (config.required_scopes && config.required_scopes.length > 0) {
          const hasRequiredScopes = this.validateScopes(
            authContext.scopes,
            config.required_scopes
          );

          if (!hasRequiredScopes) {
            throw this.createAuthError(
              'INSUFFICIENT_SCOPES',
              `Required scopes: ${config.required_scopes.join(', ')}`
            );
          }
        }

        // Apply rate limiting if configured
        if (config.rate_limit) {
          const identifier = authMethod === 'jwt'
            ? authContext.user.id
            : authContext.user.id || `api-key-${apiKeyHeader?.substring(0, 10)}`;

          const isAllowed = this.authService.checkRateLimit(
            identifier,
            config.rate_limit.requests,
            config.rate_limit.window_ms
          );

          if (!isAllowed) {
            // Log rate limit exceeded
            await this.logAuthEvent({
              event_type: 'auth_failure',
              ip_address: clientInfo.ipAddress,
              user_agent: clientInfo.userAgent,
              resource: req.path,
              action: req.method,
              details: {
                error_code: 'RATE_LIMITED',
                error_message: 'Rate limit exceeded',
                processing_time_ms: Date.now() - startTime,
                rate_limit_config: config.rate_limit,
                identifier
              },
              severity: 'medium'
            });

            // Additional audit logging for rate limiting
            await this.auditService.logRateLimitExceeded(
              identifier,
              req.path,
              config.rate_limit.requests,
              config.rate_limit.window_ms,
              clientInfo.ipAddress,
              clientInfo.userAgent,
              authContext.user.id
            );

            throw this.createAuthError('RATE_LIMITED', 'Too many requests');
          }
        }

        // Attach authentication context to request
        req.auth = authContext;
        req.user = authContext.user;

        // Log successful authentication
        await this.logAuthEvent({
          event_type: 'auth_success',
          user_id: authContext.user.id,
          session_id: authContext.session.id,
          ip_address: clientInfo.ipAddress,
          user_agent: clientInfo.userAgent,
          details: {
            auth_method: authMethod,
            scopes: authContext.scopes,
            processing_time_ms: Date.now() - startTime,
            resource: req.path,
            action: req.method
          },
          severity: 'low'
        });

        next();

      } catch (error) {
        const authError = error as AuthError;

        // Log authentication failure
        await this.logAuthEvent({
          event_type: 'auth_failure',
          ip_address: clientInfo.ipAddress,
          user_agent: clientInfo.userAgent,
          resource: req.path,
          action: req.method,
          details: {
            error_code: authError.code,
            error_message: authError.message,
            processing_time_ms: Date.now() - startTime,
            auth_header: authHeader ? '[REDACTED]' : undefined,
            api_key_provided: !!req.headers['x-api-key']
          },
          severity: this.getErrorSeverity(authError.code)
        });

        // Return appropriate error response
        this.sendAuthError(res, authError);
      }
    };
  }

  /**
   * Scope-based authorization middleware
   */
  requireScopes(scopes: AuthScope[]) {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
      if (!req.auth) {
        return this.sendAuthError(res, this.createAuthError('INVALID_TOKEN', 'Authentication required'));
      }

      const hasRequiredScopes = this.validateScopes(req.auth.scopes, scopes);

      if (!hasRequiredScopes) {
        return this.sendAuthError(
          res,
          this.createAuthError(
            'INSUFFICIENT_SCOPES',
            `Required scopes: ${scopes.join(', ')}`
          )
        );
      }

        return next();
    };
  }

  /**
   * Role-based authorization middleware
   */
  requireRole(roles: UserRole | UserRole[]) {
    const requiredRoles = Array.isArray(roles) ? roles : [roles];

    return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
      if (!req.auth) {
        return this.sendAuthError(res, this.createAuthError('INVALID_TOKEN', 'Authentication required'));
      }

      if (!requiredRoles.includes(req.auth.user.role)) {
        return this.sendAuthError(
          res,
          this.createAuthError(
            'INSUFFICIENT_SCOPES',
            `Required roles: ${requiredRoles.join(', ')}`
          )
        );
      }

        return next();
    };
  }

  /**
   * Resource-based authorization middleware
   */
  requireResourceAccess(resource: string, action: string) {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
      if (!req.auth) {
        return this.sendAuthError(res, this.createAuthError('INVALID_TOKEN', 'Authentication required'));
      }

      const requiredScopes = this.getResourceScopes(resource, action);
      const hasRequiredScopes = this.validateScopes(req.auth.scopes, requiredScopes);

      if (!hasRequiredScopes) {
        return this.sendAuthError(
          res,
          this.createAuthError(
            'INSUFFICIENT_SCOPES',
            `Insufficient permissions for ${action} on ${resource}`
          )
        );
      }

        return next();
    };
  }

  /**
   * Optional authentication middleware - attaches auth context if available but doesn't require it
   */
  optionalAuth(config: AuthMiddlewareConfig = {}) {
    return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
      const authHeader = req.headers.authorization;
      const apiKeyHeader = req.headers['x-api-key'] as string;
      const clientInfo = this.extractClientInfo(req);

      try {
        if (authHeader && authHeader.startsWith('Bearer ')) {
          const token = authHeader.substring(7);
          const authContext = await this.authenticateWithJWT(token, clientInfo);
          req.auth = authContext;
          req.user = authContext.user;
        } else if (apiKeyHeader && config.allow_api_keys !== false) {
          const authContext = await this.authenticateWithAPIKey(apiKeyHeader, clientInfo);
          req.auth = authContext;
          req.user = authContext.user;
          // API key info is stored in the auth context session
        }
      } catch (error) {
        // Optional auth failures are logged but don't block the request
        logger.warn({
          error: error instanceof Error ? error.message : String(error),
          ip: clientInfo.ipAddress
        }, 'Optional authentication failed');
      }

        return next();
    };
  }

  /**
   * JWT token authentication
   */
  private async authenticateWithJWT(token: string, clientInfo: { ipAddress: string; userAgent: string }): Promise<AuthContext> {
    try {
      const authContext = await this.authService.createAuthContext(token, clientInfo.ipAddress, clientInfo.userAgent);

      // Validate session IP address for security
      if (authContext.session.ip_address !== clientInfo.ipAddress) {
        await this.logAuthEvent({
          event_type: 'suspicious_activity',
          user_id: authContext.user.id,
          session_id: authContext.session.id,
          ip_address: clientInfo.ipAddress,
          user_agent: clientInfo.userAgent,
          details: {
            reason: 'IP address mismatch',
            session_ip: authContext.session.ip_address,
            current_ip: clientInfo.ipAddress
          },
          severity: 'high'
        });

        throw this.createAuthError('SESSION_EXPIRED', 'Session IP address mismatch');
      }

      return authContext;
    } catch (error) {
      if (error instanceof Error) {
        if (error.message === 'EXPIRED_TOKEN') {
          throw this.createAuthError('EXPIRED_TOKEN', 'Access token has expired');
        } else if (error.message === 'INVALID_TOKEN') {
          throw this.createAuthError('INVALID_TOKEN', 'Invalid access token');
        } else if (error.message === 'SESSION_EXPIRED') {
          throw this.createAuthError('SESSION_EXPIRED', 'User session has expired');
        }
      }
      throw error;
    }
  }

  /**
   * API key authentication with database validation
   */
  private async authenticateWithAPIKey(apiKey: string, clientInfo: { ipAddress: string; userAgent: string }): Promise<AuthContext> {
    try {
      // Validate API key format first
      if (!apiKey.startsWith('ck_')) {
        throw this.createAuthError('INVALID_API_KEY', 'Invalid API key format');
      }

      // Use the auth service to validate against database
      const validationResult = await this.authService.validateApiKeyWithDatabase(apiKey);

      if (!validationResult) {
        throw this.createAuthError('INVALID_API_KEY', 'API key validation failed');
      }

      const { user, scopes, apiKeyInfo } = validationResult;

      // Create auth context with validated user and scopes
      const authContext: AuthContext = {
        user: {
          id: user.id,
          username: user.username,
          role: user.role
        },
        session: {
          id: `api-key-${apiKeyInfo.id}`,
          ip_address: clientInfo.ipAddress,
          user_agent: clientInfo.userAgent
        },
        scopes,
        token_jti: randomUUID()
      };

      // Store API key info in the request for later use if needed
      // This is already available in the auth context session

      logger.info({
        apiKeyId: apiKeyInfo.key_id,
        userId: user.id,
        scopes: scopes.length,
        ipAddress: clientInfo.ipAddress
      }, 'API key authentication successful');

      return authContext;

    } catch (error) {
      logger.error({
        error: error instanceof Error ? error.message : String(error),
        apiKeyPrefix: apiKey.substring(0, Math.min(10, apiKey.length)),
        ipAddress: clientInfo.ipAddress
      }, 'API key authentication failed');

      throw this.createAuthError('INVALID_API_KEY', 'API key validation failed');
    }
  }

  /**
   * Scope validation
   */
  private validateScopes(userScopes: AuthScope[], requiredScopes: AuthScope[]): boolean {
    return requiredScopes.every(scope => userScopes.includes(scope));
  }

  /**
   * Get required scopes for a resource and action
   */
  private getResourceScopes(resource: string, action: string): AuthScope[] {
    const resourceScopeMap: Record<string, Record<string, AuthScope[]>> = {
      'memory_store': {
        'POST': [AuthScope.MEMORY_WRITE],
        'GET': [AuthScope.MEMORY_READ],
        'DELETE': [AuthScope.MEMORY_DELETE]
      },
      'memory_find': {
        'POST': [AuthScope.MEMORY_READ, AuthScope.SEARCH_BASIC],
        'GET': [AuthScope.MEMORY_READ, AuthScope.SEARCH_BASIC]
      },
      'knowledge': {
        'POST': [AuthScope.KNOWLEDGE_WRITE],
        'GET': [AuthScope.KNOWLEDGE_READ],
        'DELETE': [AuthScope.KNOWLEDGE_DELETE]
      },
      'audit': {
        'GET': [AuthScope.AUDIT_READ],
        'POST': [AuthScope.AUDIT_WRITE]
      },
      'system': {
        'GET': [AuthScope.SYSTEM_READ],
        'POST': [AuthScope.SYSTEM_MANAGE],
        'PUT': [AuthScope.SYSTEM_MANAGE],
        'DELETE': [AuthScope.SYSTEM_MANAGE]
      }
    };

    return resourceScopeMap[resource]?.[action] || [];
  }

  /**
   * Extract client information from request
   */
  private extractClientInfo(req: Request): { ipAddress: string; userAgent: string } {
    const ipAddress = req.ip ||
      req.connection.remoteAddress ||
      req.socket.remoteAddress ||
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      'unknown';

    const userAgent = req.headers['user-agent'] || 'unknown';

    return { ipAddress, userAgent };
  }

  /**
   * Create standardized authentication error
   */
  private createAuthError(code: AuthError['code'], message: string): AuthError {
    return { code, message };
  }

  /**
   * Send authentication error response
   */
  private sendAuthError(res: Response, error: AuthError): void {
    const statusCode = this.getStatusCodeForError(error.code);

    res.status(statusCode).json({
      error: {
        code: error.code,
        message: error.message,
        timestamp: new Date().toISOString()
      }
    });
  }

  /**
   * Get HTTP status code for authentication error
   */
  private getStatusCodeForError(errorCode: AuthError['code']): number {
    switch (errorCode) {
      case 'INVALID_TOKEN':
      case 'INVALID_API_KEY':
        return 401;
      case 'EXPIRED_TOKEN':
      case 'SESSION_EXPIRED':
        return 401;
      case 'INSUFFICIENT_SCOPES':
      case 'USER_INACTIVE':
        return 403;
      case 'RATE_LIMITED':
        return 429;
      default:
        return 500;
    }
  }

  /**
   * Get severity level for error logging
   */
  private getErrorSeverity(errorCode: AuthError['code']): SecurityAuditLog['severity'] {
    switch (errorCode) {
      case 'INVALID_TOKEN':
      case 'INVALID_API_KEY':
      case 'EXPIRED_TOKEN':
      case 'SESSION_EXPIRED':
        return 'medium';
      case 'INSUFFICIENT_SCOPES':
      case 'USER_INACTIVE':
        return 'low';
      case 'RATE_LIMITED':
        return 'medium';
      default:
        return 'high';
    }
  }

  /**
   * Log authentication events
   */
  private async logAuthEvent(event: Omit<SecurityAuditLog, 'id' | 'created_at'>): Promise<void> {
    try {
      await this.auditService.logSecurityAuditEvent(event as SecurityAuditLog);
    } catch (error) {
      logger.error({ error, event }, 'Failed to log authentication event');
    }
  }
}