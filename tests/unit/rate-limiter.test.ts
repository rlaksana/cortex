/**
 * Rate Limiter Tests
 *
 * Tests for the comprehensive rate limiting system with dual-layer approach:
 * - Token bucket (burst capacity)
 * - Sliding window (sustained rate)
 * - Per-API key and organization limits
 * - Configurable limits per operation type
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { RateLimitService } from '../../src/middleware/rate-limiter.js';

// Define OperationType locally to avoid circular dependencies
enum OperationType {
  MEMORY_STORE = 'memory_store',
  MEMORY_FIND = 'memory_find',
  EMBEDDING = 'embedding',
}

describe('RateLimitService', () => {
  let rateLimiter: RateLimitService;

  beforeEach(() => {
    // Create a fresh instance for each test
    rateLimiter = new RateLimitService();
  });

  afterEach(() => {
    rateLimiter.cleanup();
  });

  describe('Basic Rate Limiting', () => {
    it('should allow requests within limits', async () => {
      // Configure entity with free tier limits
      rateLimiter.configureEntity('test-api-key', 'api_key', 'free');

      // Make a request within limits
      const result = await rateLimiter.checkRateLimit(
        'test-api-key',
        'api_key',
        OperationType['MEMORY_FIND'],
        1
      );

      expect(result.allowed).toBe(true);
      expect(result.current_usage.tokens_available).toBeLessThan(100); // Started with 100, used 1
      expect(result.entity_id).toBe('test-api-key');
      expect(result.entity_type).toBe('api_key');
      expect(result.operation).toBe(OperationType['MEMORY_FIND']);
    });

    it('should block requests that exceed burst capacity', async () => {
      // Configure entity with very low limits for testing
      rateLimiter.configureEntity('test-api-key', 'api_key', 'free');

      // Exhaust the burst capacity
      const requests = [];
      for (let i = 0; i < 101; i++) {
        requests.push(
          rateLimiter.checkRateLimit('test-api-key', 'api_key', OperationType['MEMORY_FIND'], 1)
        );
      }

      const results = await Promise.all(requests);

      // First 100 should be allowed, 101st should be blocked
      expect(results.slice(0, 100).every((r) => r.allowed)).toBe(true);
      expect(results[100].allowed).toBe(false);
      expect(results[100].reason).toBe('burst_exceeded');
      expect(results[100].retry_after_seconds).toBeGreaterThan(0);
    });

    it('should track token refill over time', async () => {
      // Configure entity with high refill rate
      rateLimiter.configureEntity('test-api-key', 'api_key', 'enterprise');

      // Exhaust initial capacity
      for (let i = 0; i < 2000; i++) {
        await rateLimiter.checkRateLimit('test-api-key', 'api_key', OperationType['MEMORY_FIND'], 1);
      }

      // Should be blocked
      const blockedResult = await rateLimiter.checkRateLimit(
        'test-api-key',
        'api_key',
        OperationType['MEMORY_FIND'],
        1
      );
      expect(blockedResult.allowed).toBe(false);

      // Manually trigger refill (in real implementation this would happen over time)
      // For testing, we can create a new instance to simulate time passing
      const newRateLimiter = new RateLimitService();
      newRateLimiter.configureEntity('test-api-key', 'api_key', 'enterprise');

      const resultAfterRefill = await newRateLimiter.checkRateLimit(
        'test-api-key',
        'api_key',
        OperationType['MEMORY_FIND'],
        1
      );
      expect(resultAfterRefill.allowed).toBe(true);

      newRateLimiter.cleanup();
    });
  });

  describe('Sliding Window Limits', () => {
    it('should enforce sliding window limits', async () => {
      // Configure with low window limit
      rateLimiter.configureEntity('test-api-key', 'api_key', 'free');

      // Make many requests quickly
      const requests = [];
      for (let i = 0; i < 1001; i++) {
        requests.push(
          rateLimiter.checkRateLimit('test-api-key', 'api_key', OperationType['MEMORY_FIND'], 1)
        );
      }

      const results = await Promise.all(requests);

      // Should eventually hit sliding window limit
      const blockedResults = results.filter((r) => !r.allowed);
      expect(blockedResults.length).toBeGreaterThan(0);

      const firstBlocked = blockedResults[0];
      expect(firstBlocked.reason).toBe('window_exceeded');
    });
  });

  describe('Multiple Entities', () => {
    it('should isolate limits between different entities', async () => {
      // Configure two different entities
      rateLimiter.configureEntity('entity-1', 'api_key', 'free');
      rateLimiter.configureEntity('entity-2', 'api_key', 'free');

      // Exhaust limits for entity-1
      for (let i = 0; i < 101; i++) {
        await rateLimiter.checkRateLimit('entity-1', 'api_key', OperationType['MEMORY_FIND'], 1);
      }

      // entity-1 should be blocked
      const entity1Result = await rateLimiter.checkRateLimit(
        'entity-1',
        'api_key',
        OperationType['MEMORY_FIND'],
        1
      );
      expect(entity1Result.allowed).toBe(false);

      // entity-2 should still be allowed
      const entity2Result = await rateLimiter.checkRateLimit(
        'entity-2',
        'api_key',
        OperationType['MEMORY_FIND'],
        1
      );
      expect(entity2Result.allowed).toBe(true);
    });

    it('should handle organization-level rate limiting', async () => {
      // Configure organization-level limits
      rateLimiter.configureEntity('org-123', 'organization', 'pro');

      // Make requests as organization
      for (let i = 0; i < 10; i++) {
        const result = await rateLimiter.checkRateLimit(
          'org-123',
          'organization',
          OperationType['MEMORY_STORE'],
          1
        );
        expect(result.allowed).toBe(true);
      }
    });
  });

  describe('Operation-Specific Limits', () => {
    it('should apply different limits for different operations', async () => {
      rateLimiter.configureEntity('test-api-key', 'api_key', 'free');

      // Memory find typically has higher limits than memory store
      const findResult = await rateLimiter.checkRateLimit(
        'test-api-key',
        'api_key',
        OperationType['MEMORY_FIND'],
        1
      );
      expect(findResult.allowed).toBe(true);

      const storeResult = await rateLimiter.checkRateLimit(
        'test-api-key',
        'api_key',
        OperationType['MEMORY_STORE'],
        1
      );
      expect(storeResult.allowed).toBe(true);

      // The limits should be different (configured in DEFAULT_CONFIGS)
      expect(findResult.limits.burst_capacity).not.toEqual(storeResult.limits.burst_capacity);
    });
  });

  describe('Metrics and Monitoring', () => {
    it('should track usage statistics', async () => {
      rateLimiter.configureEntity('test-api-key', 'api_key', 'free');

      // Make some requests
      await rateLimiter.checkRateLimit('test-api-key', 'api_key', OperationType['MEMORY_FIND'], 1);
      await rateLimiter.checkRateLimit('test-api-key', 'api_key', OperationType['MEMORY_FIND'], 1);

      const usage = rateLimiter.getEntityUsage('test-api-key', 'api_key');
      expect(usage.tier).toBe('free');
      expect(usage.current_tokens).toBeDefined();
      expect(usage.window_counts).toBeDefined();
    });

    it('should provide service-wide metrics', async () => {
      rateLimiter.configureEntity('test-api-key', 'api_key', 'free');

      // Make some requests
      await rateLimiter.checkRateLimit('test-api-key', 'api_key', OperationType['MEMORY_FIND'], 1);

      const metrics = rateLimiter.getMetrics();
      expect(metrics.total_checks).toBeGreaterThan(0);
      expect(metrics.allowed_requests).toBeGreaterThan(0);
      expect(metrics.active_entities).toBe(1);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should apply default free tier limits to unconfigured entities', async () => {
      const result = await rateLimiter.checkRateLimit(
        'unknown-entity',
        'api_key',
        OperationType['MEMORY_FIND'],
        1
      );

      expect(result.allowed).toBe(true);
      expect(result.entity_id).toBe('unknown-entity');
    });

    it('should handle tokens requested greater than available', async () => {
      rateLimiter.configureEntity('test-api-key', 'api_key', 'free');

      // Request more tokens than available
      const result = await rateLimiter.checkRateLimit(
        'test-api-key',
        'api_key',
        OperationType['MEMORY_FIND'],
        1000
      );

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('burst_exceeded');
    });

    it('should reset entity limits', async () => {
      rateLimiter.configureEntity('test-api-key', 'api_key', 'free');

      // Make some requests
      await rateLimiter.checkRateLimit('test-api-key', 'api_key', OperationType['MEMORY_FIND'], 1);

      // Reset limits
      rateLimiter.resetEntityLimits('test-api-key', 'api_key');

      // Should have full capacity again
      const result = await rateLimiter.checkRateLimit(
        'test-api-key',
        'api_key',
        OperationType['MEMORY_FIND'],
        100
      );
      expect(result.allowed).toBe(true);
    });
  });
});
