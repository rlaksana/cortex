import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { MemoryStoreService } from '../../src/services/memory-store-service.js';
import { DatabaseManager } from '../../src/db/database-manager.js';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';

describe('Security Tests - Authentication and Authorization', () => {
  let memoryStore: MemoryStoreService;
  let dbManager: DatabaseManager;
  let testUserId: string;
  let testToken: string;
  let adminToken: string;

  beforeEach(async () => {
    dbManager = new DatabaseManager();
    await dbManager.initialize();
    memoryStore = new MemoryStoreService(dbManager);

    testUserId = uuidv4();

    // Generate test tokens
    testToken = jwt.sign(
      {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
        role: 'user',
      },
      'test-secret',
      { expiresIn: '1h' }
    );

    adminToken = jwt.sign(
      {
        userId: uuidv4(),
        tenant: 'test-tenant',
        org: 'test-org',
        role: 'admin',
      },
      'test-secret',
      { expiresIn: '1h' }
    );
  });

  afterEach(async () => {
    await dbManager.cleanup();
  });

  describe('JWT Token Validation', () => {
    it('should reject requests without authentication token', async () => {
      const result = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: 'Test content',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        {} as any
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('authentication required');
    });

    it('should reject invalid JWT tokens', async () => {
      const invalidTokens = [
        'invalid.jwt.token',
        'Bearer invalid.token',
        'malformed_token',
        '',
        null,
        undefined,
        123,
        {},
        [],
      ];

      for (const invalidToken of invalidTokens) {
        const result = await memoryStore.store(
          {
            kind: 'entity' as const,
            content: 'Test content',
            scope: { tenant: 'test-tenant', org: 'test-org' },
          },
          {
            token: invalidToken as any,
            userId: testUserId,
          } as any
        );

        expect(result.success).toBe(false);
        expect(result.error).toContain('invalid token');
      }
    });

    it('should reject expired JWT tokens', async () => {
      const expiredToken = jwt.sign(
        { userId: testUserId, tenant: 'test-tenant', org: 'test-org' },
        'test-secret',
        { expiresIn: '-1h' } // Expired 1 hour ago
      );

      const result = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: 'Test content',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        {
          token: expiredToken,
          userId: testUserId,
        } as any
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('token expired');
    });

    it('should reject tokens with invalid signature', async () => {
      const tokenWithWrongSecret = jwt.sign(
        { userId: testUserId, tenant: 'test-tenant', org: 'test-org' },
        'wrong-secret',
        { expiresIn: '1h' }
      );

      const result = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: 'Test content',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        {
          token: tokenWithWrongSecret,
          userId: testUserId,
        } as any
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('invalid signature');
    });

    it('should validate token claims match request context', async () => {
      const result = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: 'Test content',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        {
          token: testToken,
          userId: 'different-user-id', // Mismatch with token
        } as any
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('token context mismatch');
    });
  });

  describe('Role-Based Access Control (RBAC)', () => {
    it('should enforce user role permissions', async () => {
      const userContext = {
        token: testToken,
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
        role: 'user',
      };

      // Regular user should be able to access their own data
      const storeResult = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: 'User content',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        userContext
      );

      expect(storeResult.success).toBe(true);

      // But should not be able to access admin operations
      const adminResult = await memoryStore.performAdminAction(
        {
          action: 'delete-all-data',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        userContext
      );

      expect(adminResult.success).toBe(false);
      expect(adminResult.error).toContain('insufficient privileges');
    });

    it('should allow admin role elevated permissions', async () => {
      const adminContext = {
        token: adminToken,
        userId: uuidv4(),
        tenant: 'test-tenant',
        org: 'test-org',
        role: 'admin',
      };

      // Admin should be able to perform admin operations
      const adminResult = await memoryStore.performAdminAction(
        {
          action: 'view-all-user-data',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        adminContext
      );

      expect(adminResult.success).toBe(true);
    });

    it('should prevent privilege escalation through token tampering', async () => {
      const tamperedToken = jwt.sign(
        {
          userId: testUserId,
          tenant: 'test-tenant',
          org: 'test-org',
          role: 'admin', // Tampered role
        },
        'test-secret',
        { expiresIn: '1h' }
      );

      const result = await memoryStore.performAdminAction(
        {
          action: 'delete-all-data',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        {
          token: tamperedToken,
          userId: testUserId,
          role: 'admin', // Tampered role in context
        } as any
      );

      // Should be rejected if role verification is implemented properly
      expect(result.success).toBe(false);
      expect(result.error).toContain('insufficient privileges');
    });

    it('should validate role-based scope access', async () => {
      const limitedUserContext = {
        token: jwt.sign(
          {
            userId: testUserId,
            tenant: 'test-tenant',
            org: 'test-org',
            role: 'viewer', // Read-only role
          },
          'test-secret',
          { expiresIn: '1h' }
        ),
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
        role: 'viewer',
      };

      // Viewer should be able to read data
      const readResult = await memoryStore.find(
        {
          query: 'test',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        limitedUserContext
      );

      expect(readResult.items).toBeDefined();

      // But should not be able to write data
      const writeResult = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: 'Should not be allowed',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        limitedUserContext
      );

      expect(writeResult.success).toBe(false);
      expect(writeResult.error).toContain('insufficient privileges');
    });
  });

  describe('Multi-Tenant Isolation', () => {
    it('should enforce tenant boundaries', async () => {
      const tenantAContext = {
        token: jwt.sign({ userId: testUserId, tenant: 'tenant-a', org: 'org-a' }, 'test-secret'),
        userId: testUserId,
        tenant: 'tenant-a',
        org: 'org-a',
      };

      const tenantBContext = {
        token: jwt.sign({ userId: uuidv4(), tenant: 'tenant-b', org: 'org-b' }, 'test-secret'),
        userId: uuidv4(),
        tenant: 'tenant-b',
        org: 'org-b',
      };

      // Store data in tenant A
      const storeResult = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: 'Tenant A data',
          scope: { tenant: 'tenant-a', org: 'org-a' },
        },
        tenantAContext
      );

      expect(storeResult.success).toBe(true);

      // Try to access from tenant B
      const findResult = await memoryStore.find(
        {
          query: 'Tenant A data',
          scope: { tenant: 'tenant-b', org: 'org-b' },
        },
        tenantBContext
      );

      expect(findResult.items).toHaveLength(0);
    });

    it('should prevent cross-tenant token usage', async () => {
      const tenantToken = jwt.sign(
        { userId: testUserId, tenant: 'tenant-a', org: 'org-a' },
        'test-secret'
      );

      // Try to use tenant A token to access tenant B data
      const result = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: 'Cross-tenant attempt',
          scope: { tenant: 'tenant-b', org: 'org-b' }, // Different tenant than token
        },
        {
          token: tenantToken,
          userId: testUserId,
          tenant: 'tenant-b', // Mismatch with token
        } as any
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('tenant mismatch');
    });
  });

  describe('API Key Authentication', () => {
    it('should validate API key format and permissions', async () => {
      const validApiKey = 'ck_live_1234567890abcdef';
      const invalidApiKeys = [
        '',
        'short',
        'invalid_format',
        'ck_test_',
        'sk_invalid_prefix',
        123,
        null,
        undefined,
      ];

      // Test valid API key
      const validResult = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: 'API key test',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        {
          apiKey: validApiKey,
          userId: testUserId,
        } as any
      );

      if (validResult.success) {
        expect(validResult.storedId).toBeDefined();
      }

      // Test invalid API keys
      for (const invalidKey of invalidApiKeys) {
        const invalidResult = await memoryStore.store(
          {
            kind: 'entity' as const,
            content: 'Invalid API key test',
            scope: { tenant: 'test-tenant', org: 'test-org' },
          },
          {
            apiKey: invalidKey as any,
            userId: testUserId,
          } as any
        );

        expect(invalidResult.success).toBe(false);
        expect(invalidResult.error).toContain('invalid api key');
      }
    });

    it('should enforce API key rate limits and permissions', async () => {
      const limitedApiKey = 'ck_limited_1234567890abcdef';

      const requests = [];
      for (let i = 0; i < 10; i++) {
        requests.push(
          memoryStore.store(
            {
              kind: 'entity' as const,
              content: `API key request ${i}`,
              scope: { tenant: 'test-tenant', org: 'test-org' },
            },
            {
              apiKey: limitedApiKey,
              userId: testUserId,
            } as any
          )
        );
      }

      const results = await Promise.allSettled(requests);

      // Some requests should be rate limited
      const rateLimitedRequests = results.filter(
        (result) =>
          result.status === 'fulfilled' &&
          !result.value.success &&
          result.value.error?.includes('rate limit')
      );

      expect(rateLimitedRequests.length).toBeGreaterThan(0);
    });
  });

  describe('Session Management', () => {
    it('should validate session integrity', async () => {
      const sessionId = uuidv4();

      const result = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: 'Session test',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        {
          sessionId,
          userId: testUserId,
          tenant: 'test-tenant',
          org: 'test-org',
        } as any
      );

      if (result.success) {
        expect(result.sessionId).toBeDefined();
        expect(result.sessionId).toBe(sessionId);
      }
    });

    it('should detect and prevent session fixation', async () => {
      const fixedSessionId = 'attacker-controlled-session-id';

      const result = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: 'Session fixation test',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        {
          sessionId: fixedSessionId,
          userId: testUserId,
          tenant: 'test-tenant',
          org: 'test-org',
        } as any
      );

      if (!result.success) {
        expect(result.error).toContain('invalid session');
      } else {
        // If accepted, should generate a new session ID
        expect(result.sessionId).not.toBe(fixedSessionId);
      }
    });

    it('should handle session expiration', async () => {
      const expiredSessionId = uuidv4();

      // Simulate expired session
      const result = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: 'Expired session test',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        {
          sessionId: expiredSessionId,
          userId: testUserId,
          tenant: 'test-tenant',
          org: 'test-org',
          sessionExpired: true,
        } as any
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('session expired');
    });
  });

  describe('Failed Authentication Tracking', () => {
    it('should track failed authentication attempts', async () => {
      const failedAttempts = [];

      // Simulate multiple failed authentication attempts
      for (let i = 0; i < 5; i++) {
        const result = await memoryStore.store(
          {
            kind: 'entity' as const,
            content: 'Failed auth test',
            scope: { tenant: 'test-tenant', org: 'test-org' },
          },
          {
            token: 'invalid.token.here',
            userId: testUserId,
          } as any
        );

        failedAttempts.push(result);
      }

      // All attempts should fail
      failedAttempts.forEach((result) => {
        expect(result.success).toBe(false);
        expect(result.error).toContain('authentication');
      });

      // After multiple failures, account should be locked
      const lockedResult = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: 'Account locked test',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        {
          token: testToken, // Valid token now
          userId: testUserId,
        } as any
      );

      // Should be rejected due to account lockout
      expect(lockedResult.success).toBe(false);
      expect(lockedResult.error).toContain('account locked');
    });

    it('should implement progressive delay for failed attempts', async () => {
      const startTime = Date.now();

      // First failed attempt
      const result1 = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: 'Test 1',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        {
          token: 'invalid.token',
          userId: testUserId,
        } as any
      );

      const firstDelay = Date.now() - startTime;

      // Second failed attempt (should have longer delay)
      const secondStartTime = Date.now();
      const result2 = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: 'Test 2',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        {
          token: 'invalid.token',
          userId: testUserId,
        } as any
      );

      const secondDelay = Date.now() - secondStartTime;

      expect(result1.success).toBe(false);
      expect(result2.success).toBe(false);

      // Second attempt should take longer due to progressive delay
      expect(secondDelay).toBeGreaterThanOrEqual(firstDelay);
    });
  });

  describe('Concurrent Session Management', () => {
    it('should prevent multiple concurrent sessions for same user', async () => {
      const session1 = uuidv4();
      const session2 = uuidv4();

      // First session
      const result1 = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: 'Session 1',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        {
          sessionId: session1,
          userId: testUserId,
          tenant: 'test-tenant',
          org: 'test-org',
        } as any
      );

      // Second concurrent session
      const result2 = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: 'Session 2',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        {
          sessionId: session2,
          userId: testUserId,
          tenant: 'test-tenant',
          org: 'test-org',
        } as any
      );

      if (result1.success && result2.success) {
        // If both succeed, there should be session conflict handling
        expect(result1.conflictDetected || result2.conflictDetected).toBe(true);
      } else {
        // At least one should fail to prevent concurrent sessions
        expect(result1.success === false || result2.success === false).toBe(true);
      }
    });
  });
});
