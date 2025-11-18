/**
 * Auth Service Adapter
 *
 * Adapts the AuthService to implement the IAuthService interface.
 * Bridges interface gaps while maintaining backward compatibility.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { type AuthService } from '../../services/auth/auth-service.js';
import type { IAuthService } from '../service-interfaces.js';
import { hasPropertySimple, isObject } from '../../utils/type-guards.js';
import { asUser } from '../../utils/type-conversion.js';
import { UserRole } from '../../types/auth-types.js';
import {
  safeExtractUserProperties
} from '../../utils/type-safe-access.js';

/**
 * Adapter for Auth service
 */
export class AuthServiceAdapter implements IAuthService {
  constructor(private authService: AuthService) {}

  /**
   * Authenticate user with token
   */
  async authenticate(token: string): Promise<import('../service-interfaces.js').AuthResult> {
    try {
      const payload = await this.authService.verifyAccessToken(token);

      // Safe type conversion using type guard with proper validation
      let user: import('../service-interfaces.js').User | null = null;
      if (isObject(payload) && hasPropertySimple(payload, 'id')) {
        // Direct conversion with proper property mapping
        user = {
          id: String(payload.id),
          email: hasPropertySimple(payload, 'email') ? String(payload.email) : '',
          username: hasPropertySimple(payload, 'username') ? String(payload.username) : '',
          role: hasPropertySimple(payload, 'role')
            ? (Object.values(UserRole).includes(payload.role as UserRole) ? payload.role as UserRole : UserRole._USER)
            : UserRole._USER,
          is_active: hasPropertySimple(payload, 'is_active') ? Boolean(payload.is_active) :
                     hasPropertySimple(payload, 'isActive') ? Boolean(payload.isActive) : true,
          created_at: hasPropertySimple(payload, 'created_at') ? String(payload.created_at) :
                      hasPropertySimple(payload, 'createdAt') ? String(payload.createdAt) : new Date().toISOString(),
          updated_at: hasPropertySimple(payload, 'updated_at') ? String(payload.updated_at) :
                      hasPropertySimple(payload, 'updatedAt') ? String(payload.updatedAt) : new Date().toISOString(),
          password_hash: '', // Not available from token
        } as import('../service-interfaces.js').User;
      }

      return {
        success: !!payload,
        user,
        requiresMfa: false,
        error: user ? undefined : 'Invalid token'
      };
    } catch {
      return {
        success: false,
        user: null,
        error: 'Token validation failed'
      };
    }
  }

  /**
   * Authorize user for resource and action
   */
  async authorize(
    user: import('../service-interfaces.js').User,
    resource: string,
    action: string
  ): Promise<import('../service-interfaces.js').AuthzResult> {
    try {
      // Use the auth service's canAccessResource method
      const canAccess = this.authService.canAccessResource(user, resource, action);
      return {
        allowed: canAccess,
        reason: canAccess ? 'Access granted' : 'Access denied',
        conditions: []
      };
    } catch (error) {
      return {
        allowed: false,
        reason: `Authorization error: ${(error as Error).message}`,
        conditions: []
      };
    }
  }

  /**
   * Generate token for user
   */
  async generateToken(user: import('../service-interfaces.js').User): Promise<string> {
    try {
      // Create a temporary session and generate access token
      // Convert user to the expected type for createSession
      const convertedUser = user as any; // Cast to any to handle interface differences
      if (!convertedUser) {
        throw new Error('Invalid user data provided');
      }

      const session = this.authService.createSession(convertedUser, '127.0.0.1', 'adapter');
      const scopes = this.authService.getUserScopes(convertedUser);
      return this.authService.generateAccessToken(convertedUser, session.id, scopes);
    } catch (error) {
      throw new Error(`Failed to generate token: ${(error as Error).message}`);
    }
  }

  /**
   * Validate token and return payload
   */
  async validateToken(token: string): Promise<import('../service-interfaces.js').TokenValidationResult> {
    try {
      const payload = await this.authService.verifyAccessToken(token);
      let user: import('../service-interfaces.js').User | undefined;

      if (payload && isObject(payload) && hasPropertySimple(payload, 'id')) {
        // Direct conversion with proper property mapping
        user = {
          id: String(payload.id),
          email: hasPropertySimple(payload, 'email') ? String(payload.email) : '',
          username: hasPropertySimple(payload, 'username') ? String(payload.username) : '',
          role: hasPropertySimple(payload, 'role')
            ? (Object.values(UserRole).includes(payload.role as UserRole) ? payload.role as UserRole : UserRole._USER)
            : UserRole._USER,
          is_active: hasPropertySimple(payload, 'is_active') ? Boolean(payload.is_active) :
                     hasPropertySimple(payload, 'isActive') ? Boolean(payload.isActive) : true,
          created_at: hasPropertySimple(payload, 'created_at') ? String(payload.created_at) :
                      hasPropertySimple(payload, 'createdAt') ? String(payload.createdAt) : new Date().toISOString(),
          updated_at: hasPropertySimple(payload, 'updated_at') ? String(payload.updated_at) :
                      hasPropertySimple(payload, 'updatedAt') ? String(payload.updatedAt) : new Date().toISOString(),
          password_hash: '', // Not available from token
        } as import('../service-interfaces.js').User;
      }

      return {
        valid: !!payload,
        user,
        error: payload ? undefined : 'Invalid token'
      };
    } catch (error) {
      return {
        valid: false,
        error: (error as Error).message
      };
    }
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshToken(refreshToken: string): Promise<import('../service-interfaces.js').TokenRefreshResult> {
    try {
      // Basic implementation - would need to be enhanced based on actual AuthService capabilities
      const tokenInfo = await this.authService.verifyRefreshToken(refreshToken);
      if (tokenInfo && typeof tokenInfo === 'object' && 'sub' in tokenInfo) {
        // Note: AuthService doesn't have getUserById method, so we reconstruct user from token payload
        const payload = tokenInfo as any;
        const user = {
          id: String(payload.sub),
          email: payload.email || '',
          username: payload.username || 'unknown',
          role: payload.role || UserRole._USER,
          is_active: true,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          password_hash: '', // Not available from token
        } as import('../service-interfaces.js').User;

        const newToken = await this.generateToken(user as import('../service-interfaces.js').User);
        return {
          success: true,
          accessToken: newToken,
          refreshToken: refreshToken // Keep same refresh token for now
        };
      }
      return {
        success: false,
        error: 'Invalid refresh token'
      };
    } catch (error) {
      return {
        success: false,
        error: (error as Error).message
      };
    }
  }

  /**
   * Revoke a token
   */
  async revokeToken(token: string): Promise<boolean> {
    try {
      // Basic implementation - would need actual revoke functionality in AuthService
      await this.authService.verifyAccessToken(token); // Just validate for now
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get user permissions
   */
  async getUserPermissions(userId: string): Promise<string[]> {
    try {
      // Note: AuthService doesn't have getUserById method, return default permissions
      // In a real implementation, this would query a database or user directory
      const defaultUser = {
        id: userId,
        username: 'unknown',
        email: '',
        role: UserRole._USER,
        is_active: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        password_hash: '', // Required field
      } as import('../service-interfaces.js').User;

      const scopes = this.authService.getUserScopes(defaultUser);
      return Array.isArray(scopes) ? scopes.map(String) : [];
    } catch {
      return [];
    }
  }

  /**
   * Check if user has specific role
   */
  async checkRole(userId: string, role: string): Promise<boolean> {
    try {
      // Note: AuthService doesn't have getUserById method, return false for unknown users
      // In a real implementation, this would query a database or user directory
      return false; // Default to safe - no permissions for unknown users
    } catch {
      return false;
    }
  }
}
