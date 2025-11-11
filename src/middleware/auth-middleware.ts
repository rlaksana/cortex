/**
 * Authentication Middleware for Cortex MCP
 * Provides JWT token validation, API key authentication, and scope-based authorization
 */

import * as crypto from 'crypto';

import { type NextFunction,type Request, type Response } from 'express';

import { logger } from '@/utils/logger.js';

import { type AuthService } from '../services/auth/auth-service.js';
import {
  type AuthContext,
  type AuthError,
  type AuthMiddlewareConfig,
  AuthScope,
  type IPValidationConfig,
  type SecurityAuditLog,
  type UserRole,
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
  constructor(private _authService: AuthService) {}

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
          authContext = await this.authenticateWithJWT(token, clientInfo, config);
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
          throw this.createAuthError(
            'INVALID_TOKEN',
            'No valid authentication credentials provided'
          );
        }

        // Validate required scopes
        if (config.required_scopes && config.required_scopes.length > 0) {
          const hasRequiredScopes = this.validateScopes(authContext.scopes, config.required_scopes);

          if (!hasRequiredScopes) {
            throw this.createAuthError(
              'INSUFFICIENT_SCOPES',
              `Required scopes: ${config.required_scopes.join(', ')}`
            );
          }
        }

        // Apply rate limiting if configured
        if (config.rate_limit) {
          const identifier =
            authMethod === 'jwt'
              ? authContext.user.id
              : authContext.user.id || `api-key-${apiKeyHeader?.substring(0, 10)}`;

          const isAllowed = this._authService.checkRateLimit(
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
                identifier,
              },
              severity: 'medium',
            });

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
            action: req.method,
          },
          severity: 'low',
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
            api_key_provided: !!req.headers['x-api-key'],
          },
          severity: this.getErrorSeverity(authError.code),
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
        return this.sendAuthError(
          res,
          this.createAuthError('INVALID_TOKEN', 'Authentication required')
        );
      }

      const hasRequiredScopes = this.validateScopes(req.auth.scopes, scopes);

      if (!hasRequiredScopes) {
        return this.sendAuthError(
          res,
          this.createAuthError('INSUFFICIENT_SCOPES', `Required scopes: ${scopes.join(', ')}`)
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
        return this.sendAuthError(
          res,
          this.createAuthError('INVALID_TOKEN', 'Authentication required')
        );
      }

      if (!requiredRoles.includes(req.auth.user.role)) {
        return this.sendAuthError(
          res,
          this.createAuthError('INSUFFICIENT_SCOPES', `Required roles: ${requiredRoles.join(', ')}`)
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
        return this.sendAuthError(
          res,
          this.createAuthError('INVALID_TOKEN', 'Authentication required')
        );
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
    return async (req: AuthenticatedRequest, _res: Response, next: NextFunction) => {
      const authHeader = req.headers.authorization;
      const apiKeyHeader = req.headers['x-api-key'] as string;
      const clientInfo = this.extractClientInfo(req);

      try {
        if (authHeader && authHeader.startsWith('Bearer ')) {
          const token = authHeader.substring(7);
          const authContext = await this.authenticateWithJWT(token, clientInfo, config);
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
        logger.warn(
          {
            error: error instanceof Error ? error.message : String(error),
            ip: clientInfo.ipAddress,
          },
          'Optional authentication failed'
        );
      }

      return next();
    };
  }

  /**
   * JWT token authentication with secure IP validation
   */
  private async authenticateWithJWT(
    token: string,
    clientInfo: { ipAddress: string; userAgent: string },
    config?: AuthMiddlewareConfig
  ): Promise<AuthContext> {
    try {
      const authContext = await this._authService.createAuthContext(
        token,
        clientInfo.ipAddress,
        clientInfo.userAgent
      );

      // Perform secure IP validation based on configuration
      const ipValidationResult = await this.validateIPAddress(
        authContext.session.ip_address,
        clientInfo.ipAddress,
        authContext.user.id,
        authContext.session.id,
        clientInfo.userAgent,
        config?.ip_validation
      );

      if (!ipValidationResult.isValid) {
        await this.logAuthEvent({
          event_type: ipValidationResult.isSuspicious
            ? 'suspicious_activity'
            : 'ip_validation_failed',
          user_id: authContext.user.id,
          session_id: authContext.session.id,
          ip_address: clientInfo.ipAddress,
          user_agent: clientInfo.userAgent,
          details: {
            reason: ipValidationResult.reason,
            session_ip: authContext.session.ip_address,
            current_ip: clientInfo.ipAddress,
            validation_mode: config?.ip_validation?.mode || 'strict',
            client_info: ipValidationResult.clientInfo,
          },
          severity: ipValidationResult.isSuspicious ? 'high' : 'medium',
        });

        throw this.createAuthError('IP_VALIDATION_FAILED', ipValidationResult.reason);
      }

      // Log successful IP validation bypassed events for audit
      if (ipValidationResult.wasBypassed && config?.ip_validation?.log_ip_changes) {
        await this.logAuthEvent({
          event_type: 'ip_validation_bypassed',
          user_id: authContext.user.id,
          session_id: authContext.session.id,
          ip_address: clientInfo.ipAddress,
          user_agent: clientInfo.userAgent,
          details: {
            reason: ipValidationResult.reason,
            session_ip: authContext.session.ip_address,
            current_ip: clientInfo.ipAddress,
            validation_mode: config?.ip_validation?.mode || 'strict',
            bypass_reason: ipValidationResult.bypassReason,
          },
          severity: 'low',
        });
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
  private async authenticateWithAPIKey(
    apiKey: string,
    clientInfo: { ipAddress: string; userAgent: string }
  ): Promise<AuthContext> {
    try {
      // Validate API key format first
      if (!apiKey.startsWith('ck_')) {
        throw this.createAuthError('INVALID_API_KEY', 'Invalid API key format');
      }

      // Use the auth service to validate against database
      const validationResult = await this._authService.validateApiKeyWithDatabase(apiKey);

      if (!validationResult) {
        throw this.createAuthError('INVALID_API_KEY', 'API key validation failed');
      }

      const { user, scopes, apiKeyInfo } = validationResult;

      // Create auth context with validated user and scopes
      const authContext: AuthContext = {
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
        },
        session: {
          id: `api-key-${apiKeyInfo.id}`,
          ip_address: clientInfo.ipAddress,
          user_agent: clientInfo.userAgent,
        },
        scopes,
        token_jti: crypto.randomUUID(),
      };

      // Store API key info in the request for later use if needed
      // This is already available in the auth context session

      logger.info(
        {
          apiKeyId: apiKeyInfo.key_id,
          userId: user.id,
          scopes: scopes.length,
          ipAddress: clientInfo.ipAddress,
        },
        'API key authentication successful'
      );

      return authContext;
    } catch (error) {
      logger.error(
        {
          error: error instanceof Error ? error.message : String(error),
          apiKeyPrefix: apiKey.substring(0, Math.min(10, apiKey.length)),
          ipAddress: clientInfo.ipAddress,
        },
        'API key authentication failed'
      );

      throw this.createAuthError('INVALID_API_KEY', 'API key validation failed');
    }
  }

  /**
   * Scope validation
   */
  private validateScopes(userScopes: AuthScope[], requiredScopes: AuthScope[]): boolean {
    return requiredScopes.every((scope) => userScopes.includes(scope));
  }

  /**
   * Get required scopes for a resource and action
   */
  private getResourceScopes(resource: string, action: string): AuthScope[] {
    const resourceScopeMap: Record<string, Record<string, AuthScope[]>> = {
      memory_store: {
        POST: [AuthScope._MEMORY_WRITE],
        GET: [AuthScope._MEMORY_READ],
        DELETE: [AuthScope._MEMORY_DELETE],
      },
      memory_find: {
        POST: [AuthScope._MEMORY_READ, AuthScope._SEARCH_BASIC],
        GET: [AuthScope._MEMORY_READ, AuthScope._SEARCH_BASIC],
      },
      knowledge: {
        POST: [AuthScope._KNOWLEDGE_WRITE],
        GET: [AuthScope._KNOWLEDGE_READ],
        DELETE: [AuthScope._KNOWLEDGE_DELETE],
      },
      audit: {
        GET: [AuthScope._AUDIT_READ],
        POST: [AuthScope._AUDIT_WRITE],
      },
      system: {
        GET: [AuthScope._SYSTEM_READ],
        POST: [AuthScope._SYSTEM_MANAGE],
        PUT: [AuthScope._SYSTEM_MANAGE],
        DELETE: [AuthScope._SYSTEM_MANAGE],
      },
    };

    return resourceScopeMap[resource]?.[action] || [];
  }

  /**
   * Extract client information from request with secure IP validation
   */
  private extractClientInfo(req: Request): { ipAddress: string; userAgent: string } {
    const userAgent = req.headers['user-agent'] || 'unknown';
    const ipAddress = this.extractSecureIPAddress(req);

    return { ipAddress, userAgent };
  }

  /**
   * Extract IP address securely with validation against spoofing
   */
  private extractSecureIPAddress(req: Request): string {
    // Get the direct connection IP first (most reliable)
    const directIP = req.ip || req.socket.remoteAddress || req.connection?.remoteAddress;

    // If we have a direct IP, use it as the primary source
    if (directIP && this.isValidIPAddress(directIP)) {
      return this.normalizeIPAddress(directIP);
    }

    // Handle X-Forwarded-For header only if properly configured
    const forwardedFor = req.headers['x-forwarded-for'] as string;
    if (forwardedFor && this.isValidForwardedHeader(forwardedFor)) {
      const ips = forwardedFor.split(',').map((ip) => ip.trim());
      // The rightmost IP is the most reliable (last proxy)
      // The leftmost IP is the original client (most likely spoofed)
      for (let i = ips.length - 1; i >= 0; i--) {
        const ip = ips[i];
        if (this.isValidIPAddress(ip) && !this.isPrivateIP(ip)) {
          return this.normalizeIPAddress(ip);
        }
      }
    }

    // Fallback to other headers with validation
    const realIP = req.headers['x-real-ip'] as string;
    if (realIP && this.isValidIPAddress(realIP)) {
      return this.normalizeIPAddress(realIP);
    }

    // Final fallback to direct IP even if it's private (localhost scenarios)
    if (directIP) {
      return this.normalizeIPAddress(directIP);
    }

    return 'unknown';
  }

  /**
   * Validate IP address format and prevent injection attacks
   */
  private isValidIPAddress(ip: string): boolean {
    if (!ip || typeof ip !== 'string') return false;

    // Prevent header injection attacks
    if (ip.includes('\n') || ip.includes('\r') || ip.includes('\0')) {
      return false;
    }

    // Length validation to prevent DoS
    if (ip.length > 45) {
      // Max IPv6 address length
      return false;
    }

    // IPv4 validation
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(ip)) {
      const parts = ip.split('.');
      return parts.every((part) => {
        const num = parseInt(part, 10);
        return num >= 0 && num <= 255;
      });
    }

    // IPv6 validation (simplified - full validation would be more complex)
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    const ipv6CompressedRegex = /^([0-9a-fA-F]{1,4}:)*::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$/;

    return ipv6Regex.test(ip) || ipv6CompressedRegex.test(ip);
  }

  /**
   * Validate X-Forwarded-For header to prevent injection
   */
  private isValidForwardedHeader(header: string): boolean {
    if (!header || typeof header !== 'string') return false;

    // Prevent header injection attacks
    if (header.includes('\n') || header.includes('\r') || header.includes('\0')) {
      return false;
    }

    // Length validation
    if (header.length > 1000) {
      // Reasonable limit for forwarded header
      return false;
    }

    // Basic format validation - should contain IP-like addresses separated by commas
    const ips = header.split(',');
    if (ips.length > 10) {
      // Prevent excessive number of hops
      return false;
    }

    return ips.every((ip) => {
      const trimmed = ip.trim();
      return trimmed.length <= 45 && /^[0-9a-fA-F.:]+$/.test(trimmed);
    });
  }

  /**
   * Check if IP address is private/internal
   */
  private isPrivateIP(ip: string): boolean {
    if (!this.isValidIPAddress(ip)) return true;

    // IPv4 private ranges
    const ipv4 = ip.includes(':') ? null : ip;
    if (ipv4) {
      const parts = ipv4.split('.').map(Number);
      if (parts.length !== 4) return true;

      const [a, b] = parts;

      // 10.0.0.0/8
      if (a === 10) return true;

      // 172.16.0.0/12
      if (a === 172 && b >= 16 && b <= 31) return true;

      // 192.168.0.0/16
      if (a === 192 && b === 168) return true;

      // 127.0.0.0/8 (localhost)
      if (a === 127) return true;

      // 169.254.0.0/16 (link-local)
      if (a === 169 && b === 254) return true;

      return false;
    }

    // IPv6 private ranges (simplified)
    if (
      ip.startsWith('fc') ||
      ip.startsWith('fd') || // Unique local
      ip.startsWith('fe80') || // Link-local
      ip.startsWith('::1') || // localhost
      ip.startsWith('::ffff:127')
    ) {
      // IPv4-mapped localhost
      return true;
    }

    return false;
  }

  /**
   * Normalize IP address for consistent comparison
   */
  private normalizeIPAddress(ip: string): string {
    if (!this.isValidIPAddress(ip)) return ip;

    // IPv4 normalization
    if (!ip.includes(':')) {
      return ip.toLowerCase();
    }

    // IPv6 normalization (basic)
    const normalized = ip.toLowerCase();

    // Remove leading zeros in each group
    return normalized
      .split(':')
      .map((group) => {
        return group.replace(/^0+/, '') || '0';
      })
      .join(':');
  }

  /**
   * Comprehensive IP address validation with configurable modes
   */
  private async validateIPAddress(
    sessionIP: string,
    currentIP: string,
    _userId: string,
    _sessionId: string,
    _userAgent: string,
    config?: IPValidationConfig
  ): Promise<{
    isValid: boolean;
    reason: string;
    isSuspicious: boolean;
    wasBypassed: boolean;
    bypassReason?: string;
    clientInfo?: any;
  }> {
    // Default configuration
    const validationConfig: IPValidationConfig = {
      mode: 'strict',
      validate_headers: true,
      log_ip_changes: true,
      max_header_length: 1000,
      subnet_mask: 24, // Default for IPv4
      ...config,
    };

    // Handle disabled mode
    if (validationConfig.mode === 'disabled') {
      return {
        isValid: true,
        reason: 'IP validation disabled',
        isSuspicious: false,
        wasBypassed: true,
        bypassReason: 'Validation disabled by configuration',
      };
    }

    // Normalize both IPs for consistent comparison
    const normalizedSessionIP = this.normalizeIPAddress(sessionIP);
    const normalizedCurrentIP = this.normalizeIPAddress(currentIP);

    // Handle unknown or invalid IPs
    if (normalizedSessionIP === 'unknown' || normalizedCurrentIP === 'unknown') {
      return {
        isValid: false,
        reason: 'Invalid or unknown IP address',
        isSuspicious: true,
        wasBypassed: false,
      };
    }

    // Strict mode - exact match
    if (validationConfig.mode === 'strict') {
      if (normalizedSessionIP === normalizedCurrentIP) {
        return {
          isValid: true,
          reason: 'IP addresses match exactly',
          isSuspicious: false,
          wasBypassed: false,
        };
      } else {
        return {
          isValid: false,
          reason: 'IP address mismatch (strict validation)',
          isSuspicious: this.isSuspiciousChange(normalizedSessionIP, normalizedCurrentIP),
          wasBypassed: false,
        };
      }
    }

    // Subnet mode - CIDR-based validation
    if (validationConfig.mode === 'subnet') {
      return this.validateSubnetIP(normalizedSessionIP, normalizedCurrentIP, validationConfig);
    }

    // Fallback to strict validation
    if (normalizedSessionIP === normalizedCurrentIP) {
      return {
        isValid: true,
        reason: 'IP addresses match',
        isSuspicious: false,
        wasBypassed: false,
      };
    } else {
      return {
        isValid: false,
        reason: 'IP address validation failed',
        isSuspicious: true,
        wasBypassed: false,
      };
    }
  }

  /**
   * Validate IP addresses using subnet/CIDR matching
   */
  private validateSubnetIP(
    sessionIP: string,
    currentIP: string,
    config: IPValidationConfig
  ): {
    isValid: boolean;
    reason: string;
    isSuspicious: boolean;
    wasBypassed: boolean;
    bypassReason?: string;
    clientInfo?: any;
  } {
    try {
      // Check if IPs are in same subnet
      const sameSubnet = this.areIPsInSameSubnet(sessionIP, currentIP, config.subnet_mask || 24);

      if (sameSubnet) {
        return {
          isValid: true,
          reason: `IPs are in same subnet (/${config.subnet_mask})`,
          isSuspicious: false,
          wasBypassed: false,
        };
      }

      // Check against allowed subnets if configured
      if (config.allowed_subnets && config.allowed_subnets.length > 0) {
        const isCurrentIPAllowed = config.allowed_subnets.some((subnet) =>
          this.isIPInSubnet(currentIP, subnet)
        );

        const isSessionIPAllowed = config.allowed_subnets.some((subnet) =>
          this.isIPInSubnet(sessionIP, subnet)
        );

        if (isCurrentIPAllowed && isSessionIPAllowed) {
          return {
            isValid: true,
            reason: 'Both IPs are in allowed subnets',
            isSuspicious: false,
            wasBypassed: false,
          };
        }
      }

      // Check for trusted proxy scenarios
      if (config.trusted_proxies && config.trusted_proxies.length > 0) {
        const isCurrentIPTrusted = config.trusted_proxies.some((subnet) =>
          this.isIPInSubnet(currentIP, subnet)
        );

        if (isCurrentIPTrusted) {
          return {
            isValid: true,
            reason: 'Current IP is from trusted proxy/network',
            isSuspicious: false,
            wasBypassed: true,
            bypassReason: 'Trusted proxy validation',
          };
        }
      }

      // IP change detected - check if it's suspicious
      const isSuspicious = this.isSuspiciousChange(sessionIP, currentIP);

      return {
        isValid: false,
        reason: `IP addresses are in different subnets and not in allowed ranges`,
        isSuspicious,
        wasBypassed: false,
      };
    } catch (error) {
      logger.error({ error, sessionIP, currentIP }, 'Subnet validation error');

      return {
        isValid: false,
        reason: 'IP validation system error',
        isSuspicious: true,
        wasBypassed: false,
      };
    }
  }

  /**
   * Check if two IP addresses are in the same subnet
   */
  private areIPsInSameSubnet(ip1: string, ip2: string, subnetMask: number): boolean {
    // IPv4 subnet matching
    if (!ip1.includes(':') && !ip2.includes(':')) {
      return this.areIPv4InSameSubnet(ip1, ip2, subnetMask);
    }

    // IPv6 subnet matching (simplified)
    if (ip1.includes(':') && ip2.includes(':')) {
      return this.areIPv6InSameSubnet(ip1, ip2, subnetMask || 64);
    }

    // Mixed IPv4/IPv6 - not same subnet
    return false;
  }

  /**
   * Check if two IPv4 addresses are in the same subnet
   */
  private areIPv4InSameSubnet(ip1: string, ip2: string, subnetMask: number): boolean {
    const mask = Math.min(Math.max(subnetMask, 8), 30); // Valid subnet mask range

    const ip1Num = this.ipv4ToNumber(ip1);
    const ip2Num = this.ipv4ToNumber(ip2);

    if (ip1Num === null || ip2Num === null) return false;

    const subnetMaskNum = (0xffffffff << (32 - mask)) >>> 0;

    return (ip1Num & subnetMaskNum) === (ip2Num & subnetMaskNum);
  }

  /**
   * Check if two IPv6 addresses are in the same subnet
   */
  private areIPv6InSameSubnet(ip1: string, ip2: string, subnetMask: number): boolean {
    const mask = Math.min(Math.max(subnetMask, 8), 128);

    const ip1Bytes = this.ipv6ToBytes(ip1);
    const ip2Bytes = this.ipv6ToBytes(ip2);

    if (!ip1Bytes || !ip2Bytes) return false;

    const fullBytes = Math.floor(mask / 8);
    const remainingBits = mask % 8;

    // Compare full bytes
    for (let i = 0; i < fullBytes; i++) {
      if (ip1Bytes[i] !== ip2Bytes[i]) return false;
    }

    // Compare remaining bits
    if (remainingBits > 0 && fullBytes < 16) {
      const maskByte = (0xff << (8 - remainingBits)) & 0xff;
      return (ip1Bytes[fullBytes] & maskByte) === (ip2Bytes[fullBytes] & maskByte);
    }

    return true;
  }

  /**
   * Check if an IP address is in a given subnet
   */
  private isIPInSubnet(ip: string, subnet: string): boolean {
    try {
      const [subnetIP, maskStr] = subnet.split('/');
      const mask = parseInt(maskStr, 10);

      return this.areIPsInSameSubnet(ip, subnetIP, mask);
    } catch {
      return false;
    }
  }

  /**
   * Convert IPv4 address to number
   */
  private ipv4ToNumber(ip: string): number | null {
    try {
      const parts = ip.split('.').map(Number);
      if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
        return null;
      }

      return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
    } catch {
      return null;
    }
  }

  /**
   * Convert IPv6 address to byte array
   */
  private ipv6ToBytes(ip: string): number[] | null {
    try {
      // This is a simplified implementation
      // A full implementation would handle compressed notation (::) and IPv4-mapped addresses
      const groups = ip.split(':');
      if (groups.length !== 8) return null;

      const bytes: number[] = [];
      for (const group of groups) {
        const num = parseInt(group, 16);
        if (isNaN(num) || num < 0 || num > 0xffff) return null;

        bytes.push((num >> 8) & 0xff);
        bytes.push(num & 0xff);
      }

      return bytes;
    } catch {
      return null;
    }
  }

  /**
   * Determine if an IP change is suspicious
   */
  private isSuspiciousChange(oldIP: string, newIP: string): boolean {
    // Same IP family changes are less suspicious
    const bothIPv4 = !oldIP.includes(':') && !newIP.includes(':');
    // const bothIPv6 = oldIP.includes(':') && newIP.includes(':');

    if (bothIPv4) {
      // Check for geographical consistency (simplified)
      const oldGeoClass = this.getIPGeoClass(oldIP);
      const newGeoClass = this.getIPGeoClass(newIP);

      // Different geographic classes are more suspicious
      return oldGeoClass !== newGeoClass;
    }

    // IPv4 to IPv6 changes are suspicious unless they're mapped addresses
    if (!oldIP.includes(':') && newIP.includes(':')) {
      return !newIP.startsWith('::ffff:'); // IPv4-mapped IPv6
    }

    // IPv6 to IPv4 changes are always suspicious
    return true;
  }

  /**
   * Get geographic classification of an IP address (simplified)
   */
  private getIPGeoClass(ip: string): string {
    if (!this.isValidIPAddress(ip) || ip.includes(':')) return 'unknown';

    const num = this.ipv4ToNumber(ip);
    if (num === null) return 'unknown';

    // Simplified geographic classification based on first octet
    const firstOctet = (num >>> 24) & 0xff;

    if (firstOctet >= 1 && firstOctet <= 126) return 'public';
    if (firstOctet === 10) return 'private-10';
    if (firstOctet === 172) return 'private-172';
    if (firstOctet === 192) return 'private-192';
    if (firstOctet === 127) return 'localhost';

    return 'unknown';
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
        timestamp: new Date().toISOString(),
      },
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
      case 'IP_VALIDATION_FAILED':
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
      case 'IP_VALIDATION_FAILED':
        return 'high';
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
      // Logging disabled temporarily due to missing audit service
      logger.debug({ event }, 'Auth event (logging disabled)');
    } catch (error) {
      logger.error({ error, event }, 'Failed to log authentication event');
    }
  }
}
