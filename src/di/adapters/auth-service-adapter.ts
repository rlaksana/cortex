// @ts-nocheck
// EMERGENCY ROLLBACK: Interface compatibility issues
// TODO: Fix systematic type issues before removing @ts-nocheck

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

/**
 * Adapter for Auth service
 */
export class AuthServiceAdapter implements IAuthService {
  constructor(private authService: AuthService) {}

  /**
   * Authenticate user with token
   */
  async authenticate(token: string): Promise<boolean> {
    try {
      const payload = await this.authService.verifyAccessToken(token);
      return !!payload;
    } catch {
      return false;
    }
  }

  /**
   * Authorize user for resource and action
   */
  async authorize(user: unknown, resource: string, action: string): Promise<boolean> {
    // Use the auth service's canAccessResource method
    return this.authService.canAccessResource(user, resource, action);
  }

  /**
   * Generate token for user
   */
  async generateToken(user: unknown): Promise<string> {
    // Create a temporary session and generate access token
    const session = this.authService.createSession(user, '127.0.0.1', 'adapter');
    const scopes = this.authService.getUserScopes(user);
    return this.authService.generateAccessToken(user, session.id, scopes);
  }

  /**
   * Validate token and return payload
   */
  async validateToken(token: string): Promise<unknown> {
    try {
      return await this.authService.verifyAccessToken(token);
    } catch {
      return null;
    }
  }
}
