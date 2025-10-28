/**
 * Integration tests for Authentication System
 * Tests end-to-end authentication flows including MCP server integration
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { Server } from '@modelcontextprotocol/sdk/server';
import { AuthService } from ' '../../src/services/auth/auth-service.js';
import { AuthorizationService } from ' '../../src/services/auth/authorization-service.js';
import { ApiKeyService } from ' '../../src/services/auth/api-key-service.js';
import { AuditService } from ' '../../src/services/audit/query.js';
import { AuthMiddleware } from ' '../../src/middleware/auth-middleware.js';
import { UserRole, AuthScope } from ' '../../src/types/auth-types.js';

describe('Authentication Integration Tests', () => {
  let authService: AuthService;
  let authorizationService: AuthorizationService;
  let apiKeyService: ApiKeyService;
  let auditService: AuditService;
  let authMiddleware: AuthMiddleware;
  let mockUser: any;

  beforeEach(async () => {
    // Initialize services
    authService = new AuthService({
      jwt_secret: 'test-integration-jwt-secret-key-32-chars-minimum',
      jwt_refresh_secret: 'test-integration-refresh-secret-key-32-chars',
      jwt_expires_in: '15m',
      jwt_refresh_expires_in: '7d',
      bcrypt_rounds: 10,
      api_key_length: 32,
      session_timeout_hours: 24,
      max_sessions_per_user: 3,
      rate_limit_enabled: true
    });

    authorizationService = new AuthorizationService();
    auditService = new AuditService();
    apiKeyService = new ApiKeyService(authService, auditService);
    authMiddleware = new AuthMiddleware(authService, auditService);

    // Create mock user
    mockUser = {
      id: 'integration-test-user',
      username: 'testuser',
      email: 'test@example.com',
      password_hash: await authService.hashPassword('testpassword123!'),
      role: UserRole.USER,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
  });

  afterEach(async () => {
    // Clean up test data
    await auditService.flush();
  });

  describe('Complete Authentication Flow', () => {
    it('should authenticate user and provide JWT tokens', async () => {
      // Create session
      const session = authService.createSession(mockUser, '127.0.0.1', 'test-client');

      // Generate tokens
      const scopes = authService.getUserScopes(mockUser);
      const accessToken = authService.generateAccessToken(mockUser, session.id, scopes);
      const refreshToken = authService.generateRefreshToken(mockUser, session.id);

      // Verify access token
      const payload = authService.verifyAccessToken(accessToken);
      expect(payload.sub).toBe(mockUser.id);
      expect(payload.username).toBe(mockUser.username);
      expect(payload.role).toBe(mockUser.role);
      expect(payload.scopes).toEqual(scopes);

      // Verify refresh token
      const refreshPayload = authService.verifyRefreshToken(refreshToken);
      expect(refreshPayload.sub).toBe(mockUser.id);
      expect(refreshPayload.session_id).toBe(session.id);

      // Create auth context
      const authContext = authService.createAuthContext(accessToken, '127.0.0.1', 'test-client');
      expect(authContext.user.id).toBe(mockUser.id);
      expect(authContext.scopes).toEqual(scopes);
    });

    it('should refresh tokens successfully', async () => {
      // Create initial tokens
      const session = authService.createSession(mockUser, '127.0.0.1', 'test-client');
      const refreshToken = authService.generateRefreshToken(mockUser, session.id);

      // Refresh tokens
      const tokenResponse = await authService.refreshToken(refreshToken);

      expect(tokenResponse.access_token).toBeDefined();
      expect(tokenResponse.refresh_token).toBeDefined();
      expect(tokenResponse.token_type).toBe('Bearer');
      expect(tokenResponse.expires_in).toBeGreaterThan(0);
      expect(tokenResponse.scope).toEqual(authService.getUserScopes(mockUser));

      // Verify new access token
      const newPayload = authService.verifyAccessToken(tokenResponse.access_token);
      expect(newPayload.sub).toBe(mockUser.id);
    });

    it('should handle logout and token revocation', async () => {
      // Create session and tokens
      const session = authService.createSession(mockUser, '127.0.0.1', 'test-client');
      const accessToken = authService.generateAccessToken(mockUser, session.id, [AuthScope.MEMORY_READ]);

      // Verify token works initially
      const payload = authService.verifyAccessToken(accessToken);
      expect(payload).toBeDefined();

      // Revoke token and session
      authService.revokeToken(payload.jti);
      authService.revokeSession(session.id);

      // Token should now be invalid
      expect(() => {
        authService.verifyAccessToken(accessToken);
      }).toThrow('Token has been revoked');

      // Session should be gone
      const retrievedSession = authService.getSession(session.id);
      expect(retrievedSession).toBeNull();
    });
  });

  describe('API Key Integration', () => {
    it('should create and validate API keys', async () => {
      const createRequest = {
        name: 'Test API Key',
        scopes: [AuthScope.MEMORY_READ, AuthScope.SEARCH_BASIC],
        description: 'Integration test API key'
      };

      const result = await apiKeyService.createApiKey(mockUser, createRequest, {
        ip_address: '127.0.0.1',
        user_agent: 'test-client'
      });

      expect(result.api_key).toBeDefined();
      expect(result.key_info).toBeDefined();
      expect(result.key_info.name).toBe(createRequest.name);
      expect(result.key_info.scopes).toEqual(createRequest.scopes);
      expect(result.key_info.is_active).toBe(true);

      // Validate API key
      const validation = await apiKeyService.validateApiKey(result.api_key, {
        ip_address: '127.0.0.1',
        user_agent: 'test-client'
      });

      expect(validation.valid).toBe(true);
      expect(validation.user?.id).toBe(mockUser.id);
      expect(validation.scopes).toEqual(createRequest.scopes);

      // Create auth context from API key
      const authContext = apiKeyService.createAuthContextFromApiKey(validation, {
        ip_address: '127.0.0.1',
        user_agent: 'test-client'
      });

      expect(authContext.user.id).toBe(mockUser.id);
      expect(authContext.scopes).toEqual(createRequest.scopes);
    });

    it('should revoke API keys', async () => {
      // Create API key
      const createRequest = {
        name: 'Test API Key for Revocation',
        scopes: [AuthScope.MEMORY_READ]
      };

      const result = await apiKeyService.createApiKey(mockUser, createRequest, {
        ip_address: '127.0.0.1',
        user_agent: 'test-client'
      });

      // Validate API key works initially
      let validation = await apiKeyService.validateApiKey(result.api_key, {
        ip_address: '127.0.0.1',
        user_agent: 'test-client'
      });
      expect(validation.valid).toBe(true);

      // Revoke API key
      const revoked = await apiKeyService.revokeApiKey(mockUser, result.key_info.key_id, {
        ip_address: '127.0.0.1',
        user_agent: 'test-client'
      });
      expect(revoked).toBe(true);

      // API key should no longer work
      validation = await apiKeyService.validateApiKey(result.api_key, {
        ip_address: '127.0.0.1',
        user_agent: 'test-client'
      });
      expect(validation.valid).toBe(false);
      expect(validation.error_code).toBe('INACTIVE_KEY');
    });
  });

  describe('Authorization Integration', () => {
    it('should authorize memory operations with correct scopes', async () => {
      // Create authenticated context
      const session = authService.createSession(mockUser, '127.0.0.1', 'test-client');
      const scopes = [AuthScope.MEMORY_READ, AuthScope.MEMORY_WRITE];
      const accessToken = authService.generateAccessToken(mockUser, session.id, scopes);
      const authContext = authService.createAuthContext(accessToken, '127.0.0.1', 'test-client');

      // Test memory store write access
      const writeDecision = await authorizationService.checkAccess(
        authContext,
        'memory_store',
        'write'
      );
      expect(writeDecision.allowed).toBe(true);

      // Test memory store read access
      const readDecision = await authorizationService.checkAccess(
        authContext,
        'memory_store',
        'read'
      );
      expect(readDecision.allowed).toBe(true);

      // Test memory store delete access (should fail - no delete scope)
      const deleteDecision = await authorizationService.checkAccess(
        authContext,
        'memory_store',
        'delete'
      );
      expect(deleteDecision.allowed).toBe(false);
    });

    it('should authorize search operations with correct scopes', async () => {
      // Create authenticated context with search scopes
      const session = authService.createSession(mockUser, '127.0.0.1', 'test-client');
      const scopes = [AuthScope.MEMORY_READ, AuthScope.SEARCH_BASIC, AuthScope.SEARCH_ADVANCED];
      const accessToken = authService.generateAccessToken(mockUser, session.id, scopes);
      const authContext = authService.createAuthContext(accessToken, '127.0.0.1', 'test-client');

      // Test basic search
      const basicDecision = await authorizationService.checkAccess(
        authContext,
        'memory_find',
        'read'
      );
      expect(basicDecision.allowed).toBe(true);

      // Test advanced search
      const advancedDecision = await authorizationService.checkAccess(
        authContext,
        'memory_find',
        'advanced'
      );
      expect(advancedDecision.allowed).toBe(true);

      // Test deep search (should fail - no deep scope)
      const deepDecision = await authorizationService.checkAccess(
        authContext,
        'memory_find',
        'deep'
      );
      expect(deepDecision.allowed).toBe(false);
    });

    it('should enforce role-based access control', async () => {
      // Create admin user
      const adminUser = {
        ...mockUser,
        id: 'admin-user',
        username: 'admin',
        role: UserRole.ADMIN
      };

      const adminSession = authService.createSession(adminUser, '127.0.0.1', 'test-client');
      const adminScopes = [AuthScope.SYSTEM_MANAGE, AuthScope.USER_MANAGE];
      const adminToken = authService.generateAccessToken(adminUser, adminSession.id, adminScopes);
      const adminContext = authService.createAuthContext(adminToken, '127.0.0.1', 'test-client');

      // Test admin access to system resources
      const systemDecision = await authorizationService.checkAccess(
        adminContext,
        'system',
        'manage'
      );
      expect(systemDecision.allowed).toBe(true);

      // Test regular user cannot access system resources
      const regularSession = authService.createSession(mockUser, '127.0.0.1', 'test-client');
      const regularScopes = [AuthScope.MEMORY_READ];
      const regularToken = authService.generateAccessToken(mockUser, regularSession.id, regularScopes);
      const regularContext = authService.createAuthContext(regularToken, '127.0.0.1', 'test-client');

      const regularSystemDecision = await authorizationService.checkAccess(
        regularContext,
        'system',
        'manage'
      );
      expect(regularSystemDecision.allowed).toBe(false);
    });
  });

  describe('Audit Integration', () => {
    it('should log authentication events', async () => {
      // Create session and authenticate
      const session = authService.createSession(mockUser, '127.0.0.1', 'test-client');
      const scopes = authService.getUserScopes(mockUser);
      const accessToken = authService.generateAccessToken(mockUser, session.id, scopes);

      // Log auth success
      await auditService.logAuthSuccess(
        mockUser.id,
        session.id,
        'jwt',
        '127.0.0.1',
        'test-client',
        scopes
      );

      // Log auth failure
      await auditService.logAuthFailure(
        '192.168.1.1',
        'malicious-client',
        'Invalid credentials',
        'unknown-user'
      );

      // Flush audit logs
      await auditService.flush();

      // Get audit stats
      const stats = await auditService.getAuditStats();
      expect(stats).toBeDefined();
    });

    it('should log permission denied events', async () => {
      // Create user with limited scopes
      const session = authService.createSession(mockUser, '127.0.0.1', 'test-client');
      const limitedScopes = [AuthScope.MEMORY_READ]; // Only read access
      const accessToken = authService.generateAccessToken(mockUser, session.id, limitedScopes);
      const authContext = authService.createAuthContext(accessToken, '127.0.0.1', 'test-client');

      // Try to access write operation
      const decision = await authorizationService.checkAccess(
        authContext,
        'memory_store',
        'write'
      );

      expect(decision.allowed).toBe(false);

      // Log permission denied
      await auditService.logPermissionDenied(
        mockUser.id,
        'memory_store',
        'write',
        decision.required_scopes,
        authContext.scopes,
        '127.0.0.1',
        'test-client'
      );

      await auditService.flush();
    });

    it('should log API key events', async () => {
      // Create API key
      const createRequest = {
        name: 'Audit Test API Key',
        scopes: [AuthScope.MEMORY_READ]
      };

      const result = await apiKeyService.createApiKey(mockUser, createRequest, {
        ip_address: '127.0.0.1',
        user_agent: 'test-client'
      });

      // Revoke API key
      await apiKeyService.revokeApiKey(mockUser, result.key_info.key_id, {
        ip_address: '127.0.0.1',
        user_agent: 'test-client'
      });

      await auditService.flush();
    });
  });

  describe('Security Integration', () => {
    it('should enforce rate limiting', async () => {
      const identifier = 'test-user-rate-limit';
      const limit = 3;
      const windowMs = 1000; // 1 second

      // Allow requests up to limit
      for (let i = 0; i < limit; i++) {
        expect(authService.checkRateLimit(identifier, limit, windowMs)).toBe(true);
      }

      // Next request should be blocked
      expect(authService.checkRateLimit(identifier, limit, windowMs)).toBe(false);

      // Wait for window to reset
      await new Promise(resolve => setTimeout(resolve, 1100));

      // Should be allowed again
      expect(authService.checkRateLimit(identifier, limit, windowMs)).toBe(true);
    });

    it('should handle session security', async () => {
      // Create session
      const session = authService.createSession(mockUser, '127.0.0.1', 'test-client');
      const accessToken = authService.generateAccessToken(mockUser, session.id, [AuthScope.MEMORY_READ]);

      // Valid access with same IP
      expect(() => {
        authService.createAuthContext(accessToken, '127.0.0.1', 'test-client');
      }).not.toThrow();

      // Invalid access with different IP
      expect(() => {
        authService.createAuthContext(accessToken, '192.168.1.1', 'test-client');
      }).toThrow('SESSION_EXPIRED');
    });

    it('should handle concurrent sessions limit', async () => {
      const maxSessions = 3;
      const sessions = [];

      // Create sessions up to the limit
      for (let i = 0; i < maxSessions; i++) {
        const session = authService.createSession(mockUser, '127.0.0.1', `test-client-${i}`);
        sessions.push(session);
      }

      // All sessions should be active
      for (const session of sessions) {
        const retrieved = authService.getSession(session.id);
        expect(retrieved).toBeDefined();
        expect(retrieved!.is_active).toBe(true);
      }

      // Create one more session
      const extraSession = authService.createSession(mockUser, '127.0.0.1', 'extra-client');

      // The oldest session should be revoked
      const oldestSession = sessions[0];
      const oldestRetrieved = authService.getSession(oldestSession.id);
      expect(oldestRetrieved).toBeNull();

      // The new session should be active
      const extraRetrieved = authService.getSession(extraSession.id);
      expect(extraRetrieved).toBeDefined();
      expect(extraRetrieved!.is_active).toBe(true);
    });
  });

  describe('Error Handling Integration', () => {
    it('should handle invalid tokens gracefully', async () => {
      const invalidTokens = [
        'invalid.token.format',
        'expired.jwt.token',
        '',
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid.signature'
      ];

      for (const token of invalidTokens) {
        expect(() => {
          authService.verifyAccessToken(token);
        }).toThrow();
      }
    });

    it('should handle API key validation errors', async () => {
      const invalidApiKeys = [
        'invalid_format',
        'ck_short',
        'ck_' + 'a'.repeat(100), // Too long
        ''
      ];

      for (const apiKey of invalidApiKeys) {
        const validation = await apiKeyService.validateApiKey(apiKey, {
          ip_address: '127.0.0.1',
          user_agent: 'test-client'
        });

        expect(validation.valid).toBe(false);
        expect(validation.error).toBeDefined();
      }
    });

    it('should handle authorization decision errors', async () => {
      // Test with undefined resource
      const decision = await authorizationService.checkAccess(
        {
          user: mockUser,
          session: {
            id: 'test-session',
            ip_address: '127.0.0.1',
            user_agent: 'test-client'
          },
          scopes: [AuthScope.MEMORY_READ],
          token_jti: 'test-token'
        },
        'undefined_resource',
        'unknown_action'
      );

      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain('No access rules defined');
    });
  });

  describe('Performance Integration', () => {
    it('should handle concurrent authentication requests', async () => {
      const concurrentRequests = 10;
      const promises = [];

      // Create multiple concurrent authentication requests
      for (let i = 0; i < concurrentRequests; i++) {
        const promise = (async () => {
          const session = authService.createSession(mockUser, '127.0.0.1', `test-client-${i}`);
          const token = authService.generateAccessToken(mockUser, session.id, [AuthScope.MEMORY_READ]);
          return authService.verifyAccessToken(token);
        })();

        promises.push(promise);
      }

      // Wait for all requests to complete
      const results = await Promise.all(promises);

      // All requests should succeed
      expect(results.length).toBe(concurrentRequests);
      results.forEach(result => {
        expect(result.sub).toBe(mockUser.id);
      });
    });

    it('should handle batch authorization checks efficiently', async () => {
      const authContext = {
        user: mockUser,
        session: {
          id: 'test-session',
          ip_address: '127.0.0.1',
          user_agent: 'test-client'
        },
        scopes: [AuthScope.MEMORY_READ, AuthScope.MEMORY_WRITE, AuthScope.SEARCH_BASIC],
        token_jti: 'test-token'
      };

      const requests = [
        { resource: 'memory_store', action: 'read' },
        { resource: 'memory_store', action: 'write' },
        { resource: 'memory_find', action: 'read' },
        { resource: 'memory_find', action: 'advanced' },
        { resource: 'system', action: 'read' },
        { resource: 'knowledge', action: 'read' }
      ];

      const startTime = Date.now();
      const results = await authorizationService.checkMultipleAccess(authContext, requests);
      const duration = Date.now() - startTime;

      expect(results.size).toBe(requests.length);
      expect(duration).toBeLessThan(100); // Should complete in under 100ms

      // Check expected results
      expect(results.get('memory_store:read')?.allowed).toBe(true);
      expect(results.get('memory_store:write')?.allowed).toBe(true);
      expect(results.get('memory_find:read')?.allowed).toBe(true);
      expect(results.get('memory_find:advanced')?.allowed).toBe(false);
      expect(results.get('system:read')?.allowed).toBe(false);
      expect(results.get('knowledge:read')?.allowed).toBe(false);
    });
  });
});