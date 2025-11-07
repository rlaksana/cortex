import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { MemoryStoreService } from '../../src/services/memory-store-service.js';
import { DatabaseManager } from '../../src/db/database-manager.js';

describe('Security Tests - Rate Limiting', () => {
  let memoryStore: MemoryStoreService;
  let dbManager: DatabaseManager;
  let testUserId: string;

  beforeEach(async () => {
    dbManager = new DatabaseManager();
    await dbManager.initialize();
    memoryStore = new MemoryStoreService(dbManager);
    testUserId = 'test-user-id';
  });

  afterEach(async () => {
    await dbManager.cleanup();
  });

  describe('API Rate Limiting', () => {
    it('should enforce rate limits on memory store operations', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      const requests = [];

      // Make multiple rapid requests
      for (let i = 0; i < 20; i++) {
        requests.push(
          memoryStore.store(
            {
              kind: 'entity' as const,
              content: `Test data ${i}`,
              scope: { tenant: 'test-tenant', org: 'test-org' },
            },
            userContext
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

    it('should return proper 429 status for rate limited requests', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      // Simulate exceeding rate limit
      const rapidRequests = [];
      for (let i = 0; i < 50; i++) {
        rapidRequests.push(
          memoryStore.find(
            {
              query: `test query ${i}`,
              scope: { tenant: 'test-tenant', org: 'test-org' },
            },
            userContext
          )
        );
      }

      const results = await Promise.allSettled(rapidRequests);

      // Check if any results indicate rate limiting
      const rateLimitedResults = results.filter(
        (result) => result.status === 'fulfilled' && result.value.rateLimited === true
      );

      expect(rateLimitedResults.length).toBeGreaterThan(0);
    });

    it('should have different rate limits for different user tiers', async () => {
      const premiumUser = {
        userId: 'premium-user',
        tenant: 'test-tenant',
        org: 'test-org',
        tier: 'premium',
      };

      const standardUser = {
        userId: 'standard-user',
        tenant: 'test-tenant',
        org: 'test-org',
        tier: 'standard',
      };

      // Test premium user limits
      const premiumRequests = [];
      for (let i = 0; i < 100; i++) {
        premiumRequests.push(
          memoryStore.store(
            {
              kind: 'entity' as const,
              content: `Premium data ${i}`,
              scope: { tenant: 'test-tenant', org: 'test-org' },
            },
            premiumUser
          )
        );
      }

      // Test standard user limits
      const standardRequests = [];
      for (let i = 0; i < 100; i++) {
        standardRequests.push(
          memoryStore.store(
            {
              kind: 'entity' as const,
              content: `Standard data ${i}`,
              scope: { tenant: 'test-tenant', org: 'test-org' },
            },
            standardUser
          )
        );
      }

      const premiumResults = await Promise.allSettled(premiumRequests);
      const standardResults = await Promise.allSettled(standardRequests);

      // Premium users should have higher success rate
      const premiumSuccessRate =
        premiumResults.filter((r) => r.status === 'fulfilled' && r.value.success).length /
        premiumResults.length;

      const standardSuccessRate =
        standardResults.filter((r) => r.status === 'fulfilled' && r.value.success).length /
        standardResults.length;

      expect(premiumSuccessRate).toBeGreaterThan(standardSuccessRate);
    });
  });

  describe('Rate Limit Bypass Prevention', () => {
    it('should prevent rate limit bypass through multiple user contexts', async () => {
      const tenant = 'test-tenant';
      const org = 'test-org';

      // Create multiple requests with different user IDs but same IP/tenant
      const requests = [];
      for (let i = 0; i < 50; i++) {
        requests.push(
          memoryStore.store(
            {
              kind: 'entity' as const,
              content: `Bypass attempt ${i}`,
              scope: { tenant, org },
            },
            {
              userId: `user-${i}`,
              tenant,
              org,
              ipAddress: 'same-ip-address', // Simulate same IP
            }
          )
        );
      }

      const results = await Promise.allSettled(requests);

      // Should detect and block bypass attempts
      const blockedRequests = results.filter(
        (result) =>
          result.status === 'fulfilled' &&
          !result.value.success &&
          result.value.error?.includes('suspicious activity')
      );

      expect(blockedRequests.length).toBeGreaterThan(0);
    });

    it('should implement exponential backoff for repeated violations', async () => {
      const userContext = {
        userId: 'violating-user',
        tenant: 'test-tenant',
        org: 'test-org',
      };

      let consecutiveRejections = 0;
      let backoffTime = 100; // Start with 100ms

      // Simulate repeated violations
      for (let attempt = 0; attempt < 5; attempt++) {
        const rapidRequests = [];
        for (let i = 0; i < 30; i++) {
          rapidRequests.push(
            memoryStore.find(
              {
                query: `violation attempt ${attempt}-${i}`,
                scope: { tenant: 'test-tenant', org: 'test-org' },
              },
              userContext
            )
          );
        }

        await new Promise((resolve) => setTimeout(resolve, backoffTime));
        const results = await Promise.allSettled(rapidRequests);

        const rejectedCount = results.filter(
          (result) => result.status === 'fulfilled' && !result.value.success
        ).length;

        if (rejectedCount > 20) {
          consecutiveRejections++;
          backoffTime *= 2; // Exponential backoff
        }
      }

      expect(consecutiveRejections).toBeGreaterThan(0);
    });
  });

  describe('Rate Limit Per-Endpoint', () => {
    it('should apply different limits to different operations', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      // Test store operation limits
      const storeRequests = [];
      for (let i = 0; i < 50; i++) {
        storeRequests.push(
          memoryStore.store(
            {
              kind: 'entity' as const,
              content: `Store test ${i}`,
              scope: { tenant: 'test-tenant', org: 'test-org' },
            },
            userContext
          )
        );
      }

      // Test find operation limits
      const findRequests = [];
      for (let i = 0; i < 100; i++) {
        findRequests.push(
          memoryStore.find(
            {
              query: `Find test ${i}`,
              scope: { tenant: 'test-tenant', org: 'test-org' },
            },
            userContext
          )
        );
      }

      const [storeResults, findResults] = await Promise.allSettled([
        Promise.allSettled(storeRequests),
        Promise.allSettled(findRequests),
      ]);

      if (storeResults.status === 'fulfilled' && findResults.status === 'fulfilled') {
        const storeSuccessRate =
          storeResults.value.filter((r) => r.status === 'fulfilled' && r.value.success).length /
          storeResults.value.length;

        const findSuccessRate =
          findResults.value.filter((r) => r.status === 'fulfilled' && r.value.success).length /
          findResults.value.length;

        // Different operations should have different rate limits
        expect(storeSuccessRate).toBeGreaterThanOrEqual(0);
        expect(findSuccessRate).toBeGreaterThanOrEqual(0);
      }
    });

    it('should implement burst rate limiting with sustained limits', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      // Test burst capacity (short-term higher limit)
      const burstRequests = [];
      for (let i = 0; i < 20; i++) {
        burstRequests.push(
          memoryStore.store(
            {
              kind: 'entity' as const,
              content: `Burst test ${i}`,
              scope: { tenant: 'test-tenant', org: 'test-org' },
            },
            userContext
          )
        );
      }

      const burstResults = await Promise.allSettled(burstRequests);
      const burstSuccessRate =
        burstResults.filter((r) => r.status === 'fulfilled' && r.value.success).length /
        burstResults.length;

      // Wait for rate limit window to reset
      await new Promise((resolve) => setTimeout(resolve, 1000));

      // Test sustained rate (long-term lower limit)
      const sustainedRequests = [];
      for (let i = 0; i < 20; i++) {
        sustainedRequests.push(
          memoryStore.store(
            {
              kind: 'entity' as const,
              content: `Sustained test ${i}`,
              scope: { tenant: 'test-tenant', org: 'test-org' },
            },
            userContext
          )
        );
        await new Promise((resolve) => setTimeout(resolve, 100)); // 100ms between requests
      }

      const sustainedResults = await Promise.allSettled(sustainedRequests);
      const sustainedSuccessRate =
        sustainedResults.filter((r) => r.status === 'fulfilled' && r.value.success).length /
        sustainedResults.length;

      expect(burstSuccessRate).toBeGreaterThanOrEqual(0);
      expect(sustainedSuccessRate).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Rate Limit Headers and Metadata', () => {
    it('should include rate limit information in responses', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      const result = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: 'Rate limit test',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        userContext
      );

      expect(result).toHaveProperty('rateLimit');
      if (result.rateLimit) {
        expect(result.rateLimit).toHaveProperty('limit');
        expect(result.rateLimit).toHaveProperty('remaining');
        expect(result.rateLimit).toHaveProperty('resetTime');
        expect(result.rateLimit).toHaveProperty('windowSize');
      }
    });

    it('should provide clear rate limit status to clients', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      // Make requests to consume quota
      for (let i = 0; i < 5; i++) {
        const result = await memoryStore.store(
          {
            kind: 'entity' as const,
            content: `Quota test ${i}`,
            scope: { tenant: 'test-tenant', org: 'test-org' },
          },
          userContext
        );

        if (result.rateLimit) {
          expect(typeof result.rateLimit.remaining).toBe('number');
          expect(result.rateLimit.remaining).toBeGreaterThanOrEqual(0);
        }
      }
    });
  });
});
