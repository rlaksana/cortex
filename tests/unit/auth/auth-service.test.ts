/**
 * Unit tests for AuthService
 * Tests JWT token generation, validation, session management, and security features
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { AuthService } from '../../../src/services/auth/auth-service.ts';
import { UserRole, AuthScope, User } from '../../../src/types/auth-types.ts';

// Mock external dependencies
vi.mock('bcryptjs', () => ({
  default: {
    hash: vi.fn(),
    compare: vi.fn()
  },
  hash: vi.fn(),
  compare: vi.fn()
}));

vi.mock('jsonwebtoken', () => ({
  default: {
    sign: vi.fn(),
    verify: vi.fn(),
    TokenExpiredError: class extends Error {
      constructor(message: string, expiredAt: Date) {
        super(message);
        this.name = 'TokenExpiredError';
        (this as any).expiredAt = expiredAt;
      }
    },
    JsonWebTokenError: class extends Error {
      constructor(message: string) {
        super(message);
        this.name = 'JsonWebTokenError';
      }
    }
  },
  sign: vi.fn(),
  verify: vi.fn(),
  TokenExpiredError: class extends Error {
    constructor(message: string, expiredAt: Date) {
      super(message);
      this.name = 'TokenExpiredError';
      (this as any).expiredAt = expiredAt;
    }
  },
  JsonWebTokenError: class extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'JsonWebTokenError';
    }
  }
}));

import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const mockedBcrypt = bcrypt as any;
const mockedJwt = jwt as any;

describe('AuthService', () => {
  let authService: AuthService;
  let testConfig: any;

  beforeEach(() => {
    vi.clearAllMocks();

    testConfig = {
      jwt_secret: 'test-super-secret-jwt-key-for-testing-only',
      jwt_refresh_secret: 'test-super-secret-refresh-key-for-testing-only',
      jwt_expires_in: '15m',
      jwt_refresh_expires_in: '7d',
      bcrypt_rounds: 10,
      api_key_length: 32,
      session_timeout_hours: 24,
      max_sessions_per_user: 3,
      rate_limit_enabled: true
    };

    authService = new AuthService(testConfig);
  });

  afterEach(() => {
    // Clean up any test state
  });

  describe('Password Operations', () => {
    it('should hash and verify passwords correctly', async () => {
      const password = 'TestPassword123!';
      const hashedPassword = 'hashed-password-result';

      mockedBcrypt.hash.mockResolvedValue(hashedPassword);
      mockedBcrypt.compare.mockResolvedValue(true);

      const hash = await authService.hashPassword(password);
      expect(hash).toBe(hashedPassword);
      expect(mockedBcrypt.hash).toHaveBeenCalledWith(password, 10);

      const isValid = await authService.verifyPassword(password, hash);
      expect(isValid).toBe(true);
      expect(mockedBcrypt.compare).toHaveBeenCalledWith(password, hash);

      mockedBcrypt.compare.mockResolvedValue(false);
      const isInvalid = await authService.verifyPassword('WrongPassword', hash);
      expect(isInvalid).toBe(false);
    });

    it('should generate different hashes for the same password', async () => {
      const password = 'TestPassword123!';

      mockedBcrypt.hash
        .mockResolvedValueOnce('hashed-password-result-1')
        .mockResolvedValueOnce('hashed-password-result-2');
      mockedBcrypt.compare.mockResolvedValue(true);

      const hash1 = await authService.hashPassword(password);
      const hash2 = await authService.hashPassword(password);

      expect(hash1).not.toBe(hash2);

      const isValid1 = await authService.verifyPassword(password, hash1);
      const isValid2 = await authService.verifyPassword(password, hash2);

      expect(isValid1).toBe(true);
      expect(isValid2).toBe(true);
    });
  });

  describe('JWT Token Operations', () => {
    let testUser: User;

    beforeEach(() => {
      testUser = {
        id: 'test-user-id',
        username: 'testuser',
        email: 'test@example.com',
        password_hash: 'hashedpassword',
        role: UserRole.USER,
        is_active: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
    });

    it('should generate and verify access tokens', () => {
      const sessionId = 'test-session-id';
      const scopes = [AuthScope.MEMORY_READ, AuthScope.MEMORY_WRITE];
      const mockToken = 'mock-jwt-token';
      const mockPayload = {
        sub: testUser.id,
        username: testUser.username,
        role: testUser.role,
        scopes: scopes,
        session_id: sessionId,
        jti: 'mock-jti',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 900
      };

      mockedJwt.sign.mockReturnValue(mockToken);
      mockedJwt.verify.mockReturnValue(mockPayload);

      const token = authService.generateAccessToken(testUser, sessionId, scopes);
      expect(token).toBe(mockToken);
      expect(mockedJwt.sign).toHaveBeenCalledWith(
        expect.objectContaining({
          sub: testUser.id,
          username: testUser.username,
          role: testUser.role,
          scopes: scopes,
          session_id: sessionId
        }),
        testConfig.jwt_secret,
        expect.any(Object)
      );

      const payload = authService.verifyAccessToken(token);
      expect(payload.sub).toBe(testUser.id);
      expect(payload.username).toBe(testUser.username);
      expect(payload.role).toBe(testUser.role);
      expect(payload.scopes).toEqual(scopes);
      expect(payload.session_id).toBe(sessionId);
      expect(payload.jti).toBe('mock-jti');
    });

    it('should generate and verify refresh tokens', () => {
      const sessionId = 'test-session-id';

      const refreshToken = authService.generateRefreshToken(testUser, sessionId);
      expect(refreshToken).toBeDefined();
      expect(typeof refreshToken).toBe('string');

      const payload = authService.verifyRefreshToken(refreshToken);
      expect(payload.sub).toBe(testUser.id);
      expect(payload.session_id).toBe(sessionId);
      expect(payload.type).toBe('refresh');
    });

    it('should reject invalid tokens', () => {
      const invalidToken = 'invalid.token.here';

      mockedJwt.verify.mockImplementation(() => {
        throw new mockedJwt.JsonWebTokenError('invalid signature');
      });

      expect(() => {
        authService.verifyAccessToken(invalidToken);
      }).toThrow('INVALID_TOKEN');

      expect(() => {
        authService.verifyRefreshToken(invalidToken);
      }).toThrow('INVALID_REFRESH_TOKEN');
    });

    it('should reject expired tokens', () => {
      const token = 'expired-token';

      mockedJwt.verify.mockImplementation(() => {
        throw new mockedJwt.TokenExpiredError('jwt expired', new Date());
      });

      expect(() => {
        authService.verifyAccessToken(token);
      }).toThrow('EXPIRED_TOKEN');
    });

    it('should revoke tokens correctly', () => {
      const mockToken = 'mock-jwt-token';
      const mockPayload = {
        sub: testUser.id,
        username: testUser.username,
        role: testUser.role,
        scopes: [AuthScope.MEMORY_READ],
        session_id: 'session',
        jti: 'revoke-test-jti',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 900
      };

      mockedJwt.sign.mockReturnValue(mockToken);
      mockedJwt.verify.mockReturnValue(mockPayload);

      const token = authService.generateAccessToken(testUser, 'session', [AuthScope.MEMORY_READ]);

      // Verify token works initially
      const payload = authService.verifyAccessToken(token);
      expect(payload.jti).toBe('revoke-test-jti');

      // Revoke token
      authService.revokeToken(payload.jti);

      // Token should now be rejected
      expect(() => {
        authService.verifyAccessToken(token);
      }).toThrow('Token has been revoked');
    });
  });

  describe('Session Management', () => {
    let testUser: User;

    beforeEach(() => {
      testUser = {
        id: 'test-user-id',
        username: 'testuser',
        email: 'test@example.com',
        password_hash: 'hashedpassword',
        role: UserRole.USER,
        is_active: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
    });

    it('should create and retrieve sessions', () => {
      const ipAddress = '127.0.0.1';
      const userAgent = 'test-agent';

      const session = authService.createSession(testUser, ipAddress, userAgent);

      expect(session.id).toBeDefined();
      expect(session.user_id).toBe(testUser.id);
      expect(session.ip_address).toBe(ipAddress);
      expect(session.user_agent).toBe(userAgent);
      expect(session.is_active).toBe(true);
      expect(session.created_at).toBeDefined();
      expect(session.expires_at).toBeDefined();

      const retrieved = authService.getSession(session.id);
      expect(retrieved).toBeDefined();
      expect(retrieved!.id).toBe(session.id);
      expect(retrieved!.user_id).toBe(testUser.id);
    });

    it('should revoke sessions correctly', () => {
      const session = authService.createSession(testUser, '127.0.0.1', 'test-agent');

      // Session should be active initially
      let retrieved = authService.getSession(session.id);
      expect(retrieved).toBeDefined();
      expect(retrieved!.is_active).toBe(true);

      // Revoke session
      authService.revokeSession(session.id);

      // Session should no longer be retrievable
      retrieved = authService.getSession(session.id);
      expect(retrieved).toBeNull();
    });

    it('should limit sessions per user', () => {
      const maxSessions = testConfig.max_sessions_per_user;

      // Create sessions up to the limit
      const sessions = [];
      for (let i = 0; i < maxSessions; i++) {
        const session = authService.createSession(testUser, '127.0.0.1', `test-agent-${i}`);
        sessions.push(session);
      }

      // All sessions should be active
      for (const session of sessions) {
        const retrieved = authService.getSession(session.id);
        expect(retrieved).toBeDefined();
        expect(retrieved!.is_active).toBe(true);
      }

      // Create one more session
      const extraSession = authService.createSession(testUser, '127.0.0.1', 'extra-agent');

      // The oldest session should be revoked
      const oldestSession = sessions[0];
      const oldestRetrieved = authService.getSession(oldestSession.id);
      expect(oldestRetrieved).toBeNull();

      // The new session should be active
      const extraRetrieved = authService.getSession(extraSession.id);
      expect(extraRetrieved).toBeDefined();
      expect(extraRetrieved!.is_active).toBe(true);
    });

    it('should revoke all user sessions', () => {
      // Create multiple sessions
      const sessions = [];
      for (let i = 0; i < 3; i++) {
        const session = authService.createSession(testUser, '127.0.0.1', `test-agent-${i}`);
        sessions.push(session);
      }

      // All sessions should be active
      for (const session of sessions) {
        const retrieved = authService.getSession(session.id);
        expect(retrieved).toBeDefined();
        expect(retrieved!.is_active).toBe(true);
      }

      // Revoke all sessions
      authService.revokeAllUserSessions(testUser.id);

      // All sessions should be revoked
      for (const session of sessions) {
        const retrieved = authService.getSession(session.id);
        expect(retrieved).toBeNull();
      }
    });
  });

  describe('API Key Operations', () => {
    it('should generate API keys with correct format', () => {
      const { keyId, key } = authService.generateApiKey();

      expect(keyId).toMatch(/^ck_[a-f0-9]{16}$/i);
      expect(key).toMatch(/^ck_[a-f0-9]{64}$/i);
      expect(keyId).not.toBe(key);
    });

    it('should hash and verify API keys', async () => {
      const { key } = authService.generateApiKey();

      const hash = await authService.hashApiKey(key);
      expect(hash).toBeDefined();
      expect(hash).not.toBe(key);

      const isValid = await authService.verifyApiKey(key, hash);
      expect(isValid).toBe(true);

      const isInvalid = await authService.verifyApiKey('wrong-key', hash);
      expect(isInvalid).toBe(false);
    });

    it('should generate unique API keys', () => {
      const { keyId: keyId1, key: key1 } = authService.generateApiKey();
      const { keyId: keyId2, key: key2 } = authService.generateApiKey();

      expect(keyId1).not.toBe(keyId2);
      expect(key1).not.toBe(key2);
    });
  });

  describe('Authorization Operations', () => {
    let testUser: User;

    beforeEach(() => {
      testUser = {
        id: 'test-user-id',
        username: 'testuser',
        email: 'test@example.com',
        password_hash: 'hashedpassword',
        role: UserRole.USER,
        is_active: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
    });

    it('should return correct scopes for user roles', () => {
      const userScopes = authService.getUserScopes(testUser);
      expect(userScopes).toContain(AuthScope.MEMORY_READ);
      expect(userScopes).toContain(AuthScope.MEMORY_WRITE);
      expect(userScopes).toContain(AuthScope.KNOWLEDGE_READ);
      expect(userScopes).toContain(AuthScope.KNOWLEDGE_WRITE);
      expect(userScopes).toContain(AuthScope.SEARCH_BASIC);
      expect(userScopes).toContain(AuthScope.SEARCH_ADVANCED);

      const maxScopes = authService.getUserMaxScopes(testUser);
      expect(maxScopes.length).toBeGreaterThanOrEqual(userScopes.length);
    });

    it('should validate scopes correctly', () => {
      const userScopes = [AuthScope.MEMORY_READ, AuthScope.MEMORY_WRITE];
      const requiredScopes = [AuthScope.MEMORY_READ];

      expect(authService.validateScopes(userScopes, requiredScopes)).toBe(true);

      const missingScopes = [AuthScope.SYSTEM_MANAGE];
      expect(authService.validateScopes(userScopes, missingScopes)).toBe(false);
    });

    it('should check resource access permissions', () => {
      const userScopes = [AuthScope.MEMORY_READ, AuthScope.MEMORY_WRITE];

      expect(authService.canAccessResource(testUser, 'memory_store', 'read', userScopes)).toBe(true);
      expect(authService.canAccessResource(testUser, 'memory_store', 'write', userScopes)).toBe(true);
      expect(authService.canAccessResource(testUser, 'memory_store', 'delete', userScopes)).toBe(false);
      expect(authService.canAccessResource(testUser, 'system', 'manage', userScopes)).toBe(false);
    });
  });

  describe('Authentication Context', () => {
    let testUser: User;
    let testToken: string;

    beforeEach(() => {
      testUser = {
        id: 'test-user-id',
        username: 'testuser',
        email: 'test@example.com',
        password_hash: 'hashedpassword',
        role: UserRole.USER,
        is_active: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };

      const sessionId = 'test-session-id';
      const scopes = [AuthScope.MEMORY_READ, AuthScope.MEMORY_WRITE];
      testToken = authService.generateAccessToken(testUser, sessionId, scopes);

      // Create the session
      authService.createSession(testUser, '127.0.0.1', 'test-agent');
    });

    it('should create authentication context from valid token', () => {
      const authContext = authService.createAuthContext(testToken, '127.0.0.1', 'test-agent');

      expect(authContext.user.id).toBe(testUser.id);
      expect(authContext.user.username).toBe(testUser.username);
      expect(authContext.user.role).toBe(testUser.role);
      expect(authContext.scopes).toContain(AuthScope.MEMORY_READ);
      expect(authContext.scopes).toContain(AuthScope.MEMORY_WRITE);
      expect(authContext.token_jti).toBeDefined();
    });

    it('should reject authentication context for expired sessions', () => {
      // Manually expire the session
      const session = authService.getSession('test-session-id');
      if (session) {
        (session as any).expires_at = new Date(Date.now() - 1000).toISOString();
      }

      expect(() => {
        authService.createAuthContext(testToken, '127.0.0.1', 'test-agent');
      }).toThrow('SESSION_EXPIRED');
    });

    it('should detect IP address mismatches', () => {
      // Create session with different IP
      const session = authService.createSession(testUser, '192.168.1.1', 'test-agent');
      const token = authService.generateAccessToken(testUser, session.id, [AuthScope.MEMORY_READ]);

      expect(() => {
        authService.createAuthContext(token, '127.0.0.1', 'test-agent');
      }).toThrow('SESSION_EXPIRED');
    });
  });

  describe('Token Refresh', () => {
    let testUser: User;
    let testRefreshToken: string;

    beforeEach(() => {
      testUser = {
        id: 'test-user-id',
        username: 'testuser',
        email: 'test@example.com',
        password_hash: 'hashedpassword',
        role: UserRole.USER,
        is_active: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };

      const sessionId = 'test-session-id';
      authService.createSession(testUser, '127.0.0.1', 'test-agent');
      testRefreshToken = authService.generateRefreshToken(testUser, sessionId);
    });

    it('should refresh tokens successfully', async () => {
      const tokenResponse = await authService.refreshToken(testRefreshToken);

      expect(tokenResponse.access_token).toBeDefined();
      expect(tokenResponse.refresh_token).toBeDefined();
      expect(tokenResponse.token_type).toBe('Bearer');
      expect(tokenResponse.expires_in).toBeGreaterThan(0);
      expect(tokenResponse.scope).toBeDefined();
      expect(Array.isArray(tokenResponse.scope)).toBe(true);
    });

    it('should reject invalid refresh tokens', async () => {
      const invalidRefreshToken = 'invalid.refresh.token';

      await expect(authService.refreshToken(invalidRefreshToken)).rejects.toThrow();
    });
  });

  describe('Rate Limiting', () => {
    it('should enforce rate limits', () => {
      const identifier = 'test-user';
      const limit = 5;
      const windowMs = 60000; // 1 minute

      // Allow requests up to limit
      for (let i = 0; i < limit; i++) {
        expect(authService.checkRateLimit(identifier, limit, windowMs)).toBe(true);
      }

      // Next request should be blocked
      expect(authService.checkRateLimit(identifier, limit, windowMs)).toBe(false);
    });

    it('should reset rate limits after window expires', (done) => {
      const identifier = 'test-user';
      const limit = 1;
      const windowMs = 10; // 10ms

      // First request should be allowed
      expect(authService.checkRateLimit(identifier, limit, windowMs)).toBe(true);

      // Second request should be blocked
      expect(authService.checkRateLimit(identifier, limit, windowMs)).toBe(false);

      // Wait for window to reset
      setTimeout(() => {
        expect(authService.checkRateLimit(identifier, limit, windowMs)).toBe(true);
        done();
      }, 20);
    });
  });

  describe('Health Status', () => {
    it('should return healthy status', () => {
      const health = authService.getHealthStatus();

      expect(health.status).toBe('healthy');
      expect(health.details).toBeDefined();
      expect(health.details.active_sessions).toBeGreaterThanOrEqual(0);
      expect(health.details.blacklisted_tokens).toBeGreaterThanOrEqual(0);
      expect(health.details.rate_limit_entries).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Configuration Validation', () => {
    it('should validate configuration on initialization', () => {
      expect(() => {
        new AuthService({
          ...testConfig,
          jwt_secret: 'short' // Too short
        });
      }).toThrow(expect.any(Error));

      expect(() => {
        new AuthService({
          ...testConfig,
          jwt_refresh_secret: 'short' // Too short
        });
      }).toThrow(expect.any(Error));
    });
  });
});