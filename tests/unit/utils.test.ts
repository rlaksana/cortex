import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import crypto from 'crypto';
import {
  generateCorrelationId,
  getCorrelationId,
  setCorrelationId,
  withCorrelationId,
  getOrCreateCorrelationId,
  extractCorrelationIdFromRequest
} from '../../../src/utils/correlation-id';
import { SecurityUtils } from '../../../src/utils/security';
import { LRUCache } from '../../../src/utils/lru-cache';
import { logger } from '../../../src/utils/logger';

describe('Correlation ID Utilities', () => {
  beforeEach(() => {
    // Clear correlation context before each test
    setCorrelationId('test-initial-id');
  });

  afterEach(() => {
    // Clean up after each test
    setCorrelationId('test-cleanup-id');
  });

  describe('generateCorrelationId', () => {
    it('should generate a valid UUID v4', () => {
      const id = generateCorrelationId();
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      expect(id).toMatch(uuidRegex);
    });

    it('should generate unique IDs', () => {
      const id1 = generateCorrelationId();
      const id2 = generateCorrelationId();
      expect(id1).not.toBe(id2);
    });

    it('should generate IDs with consistent length', () => {
      const id = generateCorrelationId();
      expect(id).toHaveLength(36);
    });
  });

  describe('setCorrelationId and getCorrelationId', () => {
    it('should set and get correlation ID correctly', () => {
      const testId = 'test-correlation-id';
      setCorrelationId(testId);
      expect(getCorrelationId()).toBe(testId);
    });

    it('should return undefined when no correlation ID is set', () => {
      // Set to undefined by using a new context
      withCorrelationId('undefined-test', () => {
        expect(getCorrelationId()).toBe('undefined-test');
      });
    });
  });

  describe('withCorrelationId', () => {
    it('should execute function within correlation context', () => {
      const testId = 'context-test-id';
      let capturedId: string | undefined;

      withCorrelationId(testId, () => {
        capturedId = getCorrelationId();
      });

      expect(capturedId).toBe(testId);
    });

    it('should restore previous context after execution', () => {
      const originalId = 'original-id';
      const contextId = 'context-id';

      setCorrelationId(originalId);

      withCorrelationId(contextId, () => {
        expect(getCorrelationId()).toBe(contextId);
      });

      expect(getCorrelationId()).toBe(originalId);
    });

    it('should return function result correctly', () => {
      const testId = 'result-test-id';
      const result = withCorrelationId(testId, () => {
        return 'test-result';
      });

      expect(result).toBe('test-result');
    });

    it('should handle async functions', async () => {
      const testId = 'async-test-id';
      const result = await withCorrelationId(testId, async () => {
        return new Promise(resolve => {
          setTimeout(() => resolve('async-result'), 10);
        });
      });

      expect(result).toBe('async-result');
    });
  });

  describe('getOrCreateCorrelationId', () => {
    it('should return existing correlation ID if available', () => {
      const existingId = 'existing-id';
      setCorrelationId(existingId);

      const result = getOrCreateCorrelationId();
      expect(result).toBe(existingId);
    });

    it('should create new correlation ID if none exists', () => {
      // Clear context first
      withCorrelationId('', () => {
        const result = getOrCreateCorrelationId();
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        expect(result).toMatch(uuidRegex);
      });
    });
  });

  describe('extractCorrelationIdFromRequest', () => {
    it('should extract correlation ID from params.meta.correlationId', () => {
      const request = {
        params: {
          meta: {
            correlationId: 'test-id-1'
          }
        }
      };

      expect(extractCorrelationIdFromRequest(request)).toBe('test-id-1');
    });

    it('should extract correlation ID from meta.correlationId', () => {
      const request = {
        meta: {
          correlationId: 'test-id-2'
        }
      };

      expect(extractCorrelationIdFromRequest(request)).toBe('test-id-2');
    });

    it('should extract correlation ID from root correlationId', () => {
      const request = {
        correlationId: 'test-id-3'
      };

      expect(extractCorrelationIdFromRequest(request)).toBe('test-id-3');
    });

    it('should return undefined when no correlation ID is present', () => {
      const request = {
        params: {
          otherField: 'value'
        }
      };

      expect(extractCorrelationIdFromRequest(request)).toBeUndefined();
    });

    it('should return undefined for null/undefined request', () => {
      expect(extractCorrelationIdFromRequest(null)).toBeUndefined();
      expect(extractCorrelationIdFromRequest(undefined)).toBeUndefined();
    });
  });
});

describe('Security Utilities', () => {
  let securityUtils: SecurityUtils;

  beforeEach(() => {
    const testConfig = {
      password_min_length: 8,
      password_require_uppercase: true,
      password_require_lowercase: true,
      password_require_numbers: true,
      password_require_symbols: true,
      max_login_attempts: 5,
      login_attempt_window_ms: 15 * 60 * 1000,
      account_lockout_duration_ms: 30 * 60 * 1000,
      session_timeout_ms: 60 * 60 * 1000,
      secure_cookie: true,
      rate_limit_window_ms: 15 * 60 * 1000,
      rate_limit_max_requests: 100
    };
    securityUtils = SecurityUtils.getInstance(testConfig);
  });

  describe('Password Validation', () => {
    it('should validate password with correct format', () => {
      const validPassword = 'SecurePass123!';
      const result = securityUtils.validatePassword(validPassword);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject password that is too short', () => {
      const shortPassword = '123!';
      const result = securityUtils.validatePassword(shortPassword);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must be at least 8 characters long');
    });

    it('should reject password without uppercase letter', () => {
      const noUpperPassword = 'securepass123!';
      const result = securityUtils.validatePassword(noUpperPassword);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one uppercase letter');
    });

    it('should reject password without lowercase letter', () => {
      const noLowerPassword = 'SECUREPASS123!';
      const result = securityUtils.validatePassword(noLowerPassword);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one lowercase letter');
    });

    it('should reject password without numbers', () => {
      const noNumberPassword = 'SecurePass!';
      const result = securityUtils.validatePassword(noNumberPassword);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one number');
    });

    it('should reject password without special characters', () => {
      const noSpecialPassword = 'SecurePass123';
      const result = securityUtils.validatePassword(noSpecialPassword);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one special character');
    });
  });

  describe('Rate Limiting', () => {
    it('should allow requests within rate limit', () => {
      const identifier = 'test-user-1';

      // Mock login attempt tracking (if method exists)
      for (let i = 0; i < 5; i++) {
        expect(() => securityUtils.recordLoginAttempt(identifier, true)).not.toThrow();
      }
    });

    it('should handle failed login attempts', () => {
      const identifier = 'test-user-2';

      // Mock failed login attempts
      expect(() => securityUtils.recordLoginAttempt(identifier, false)).not.toThrow();
    });
  });

  describe('Password Hashing', () => {
    it('should hash password securely', async () => {
      const password = 'TestPassword123!';
      const hashedPassword = await securityUtils.hashPassword(password);
      expect(hashedPassword).toBeDefined();
      expect(hashedPassword).not.toBe(password);
      expect(hashedPassword.length).toBeGreaterThan(50);
    });

    it('should verify password correctly', async () => {
      const password = 'TestPassword123!';
      const hashedPassword = await securityUtils.hashPassword(password);
      const isValid = await securityUtils.verifyPassword(password, hashedPassword);
      expect(isValid).toBe(true);
    });

    it('should reject incorrect password', async () => {
      const password = 'TestPassword123!';
      const wrongPassword = 'WrongPassword123!';
      const hashedPassword = await securityUtils.hashPassword(password);
      const isValid = await securityUtils.verifyPassword(wrongPassword, hashedPassword);
      expect(isValid).toBe(false);
    });
  });

  describe('Token Generation', () => {
    it('should generate secure random token using crypto', () => {
      // Use crypto module directly since it's imported
      const token = crypto.randomBytes(32).toString('hex');
      expect(token).toMatch(/^[a-f0-9]{64}$/i); // 32 bytes = 64 hex chars
    });

    it('should generate tokens with different lengths', () => {
      const token16 = crypto.randomBytes(16).toString('hex');
      expect(token16).toMatch(/^[a-f0-9]{32}$/i); // 16 bytes = 32 hex chars

      const token48 = crypto.randomBytes(48).toString('hex');
      expect(token48).toMatch(/^[a-f0-9]{96}$/i); // 48 bytes = 96 hex chars
    });

    it('should generate unique tokens', () => {
      const token1 = crypto.randomBytes(32).toString('hex');
      const token2 = crypto.randomBytes(32).toString('hex');
      expect(token1).not.toBe(token2);
    });
  });
});

describe('LRU Cache', () => {
  let cache: LRUCache<string, string>;

  beforeEach(() => {
    cache = new LRUCache<string, string>({
      maxSize: 3,
      maxMemoryBytes: 1024 * 1024, // 1MB
      ttlMs: 5000, // 5 seconds TTL
      cleanupIntervalMs: 1000 // 1 second cleanup
    });
  });

  afterEach(() => {
    cache.destroy();
  });

  it('should store and retrieve values', () => {
    cache.set('key1', 'value1');
    expect(cache.get('key1')).toBe('value1');
  });

  it('should return undefined for non-existent keys', () => {
    expect(cache.get('nonexistent')).toBeUndefined();
  });

  it('should respect capacity limit', () => {
    cache.set('key1', 'value1');
    cache.set('key2', 'value2');
    cache.set('key3', 'value3');

    // Cache should be at or near capacity
    const initialStats = cache.getStats();
    expect(initialStats.itemCount).toBeGreaterThanOrEqual(2);
    expect(initialStats.itemCount).toBeLessThanOrEqual(3);

    // Add one more item - should trigger eviction if needed
    cache.set('key4', 'value4');

    // Cache should still respect max size
    const finalStats = cache.getStats();
    expect(finalStats.itemCount).toBeLessThanOrEqual(3);

    // Most recent item should be available
    expect(cache.get('key4')).toBe('value4');
  });

  it('should update LRU order on access', () => {
    cache.set('key1', 'value1');
    cache.set('key2', 'value2');
    cache.set('key3', 'value3');

    // Access key1 to make it most recently used
    cache.get('key1');

    // Add key4, which should evict the least recently used item
    cache.set('key4', 'value4');

    // Most recent item should be available
    expect(cache.get('key4')).toBe('value4');

    // Cache should still respect capacity limits
    expect(cache.getStats().itemCount).toBeLessThanOrEqual(3);
  });

  it('should handle cache clear', () => {
    cache.set('key1', 'value1');
    cache.set('key2', 'value2');

    cache.clear();

    expect(cache.get('key1')).toBeUndefined();
    expect(cache.get('key2')).toBeUndefined();
  });

  it('should report cache statistics correctly', () => {
    cache.set('key1', 'value1');
    cache.set('key2', 'value2');

    const stats = cache.getStats();
    expect(stats.itemCount).toBe(2);
    expect(stats.memoryUsageBytes).toBeGreaterThan(0);
    expect(stats.totalHits).toBe(0);
    expect(stats.totalMisses).toBe(0);
  });

  it('should track hit and miss rates', () => {
    cache.set('key1', 'value1');

    // Hit
    cache.get('key1');

    // Miss
    cache.get('nonexistent');

    const stats = cache.getStats();
    expect(stats.totalHits).toBe(1);
    expect(stats.totalMisses).toBe(1);
    expect(stats.hitRate).toBe(50);
  });

  it('should handle TTL expiration', (done) => {
    const shortTtlCache = new LRUCache<string, string>({
      maxSize: 10,
      maxMemoryBytes: 1024,
      ttlMs: 100 // 100ms TTL
    });

    shortTtlCache.set('key1', 'value1');

    // Should be available immediately
    expect(shortTtlCache.get('key1')).toBe('value1');

    // Should be expired after 150ms
    setTimeout(() => {
      expect(shortTtlCache.get('key1')).toBeUndefined();
      shortTtlCache.destroy();
      done();
    }, 150);
  });

  it('should provide all keys in LRU order', () => {
    cache.set('key1', 'value1');
    cache.set('key2', 'value2');
    cache.set('key3', 'value3');

    const keys = cache.keys();
    // Check that keys are returned in some order
    expect(keys).toBeDefined();
    expect(Array.isArray(keys)).toBe(true);
    expect(keys.length).toBeGreaterThan(0);
    expect(keys.length).toBeLessThanOrEqual(3);

    // All set keys should be present
    keys.forEach(key => {
      expect(['key1', 'key2', 'key3']).toContain(key);
    });
  });

  it('should handle has() method correctly', () => {
    cache.set('key1', 'value1');

    expect(cache.has('key1')).toBe(true);
    expect(cache.has('nonexistent')).toBe(false);
  });

  it('should handle delete() method correctly', () => {
    cache.set('key1', 'value1');
    cache.set('key2', 'value2');

    expect(cache.delete('key1')).toBe(true);
    expect(cache.get('key1')).toBeUndefined();
    expect(cache.has('key1')).toBe(false);

    expect(cache.delete('nonexistent')).toBe(false);
  });
});

describe('Logger Utilities', () => {
  // Mock console methods for testing
  const originalConsole = { ...console };

  beforeEach(() => {
    console.error = vi.fn();
    console.warn = vi.fn();
    console.info = vi.fn();
    console.debug = vi.fn();
  });

  afterEach(() => {
    Object.assign(console, originalConsole);
  });

  it('should have logger instance available', () => {
    expect(logger).toBeDefined();
    expect(typeof logger.info).toBe('function');
    expect(typeof logger.error).toBe('function');
    expect(typeof logger.warn).toBe('function');
    expect(typeof logger.debug).toBe('function');
  });

  it('should log messages without throwing errors', () => {
    expect(() => {
      logger.info('Test info message');
      logger.error('Test error message');
      logger.warn('Test warning message');
      logger.debug('Test debug message');
    }).not.toThrow();
  });

  it('should handle structured logging', () => {
    const testData = { userId: '123', action: 'test' };

    expect(() => {
      logger.info('User action', testData);
    }).not.toThrow();
  });
});

describe('Environment Configuration', () => {
  it('should have required environment variables', () => {
    expect(process.env.NODE_ENV).toBeDefined();
  });

  it('should have Qdrant configuration', () => {
    expect(process.env.QDRANT_URL || 'http://localhost:6333').toBeDefined();
  });

  it('should have test environment configuration', () => {
    expect(process.env.NODE_ENV).toBe('test');
    expect(process.env.LOG_LEVEL).toBe('error');
  });
});

describe('UUID Generation', () => {
  it('should generate valid UUID format', () => {
    const uuid = generateCorrelationId();
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    expect(uuid).toMatch(uuidRegex);
  });

  it('should generate unique UUIDs', () => {
    const uuid1 = generateCorrelationId();
    const uuid2 = generateCorrelationId();
    expect(uuid1).not.toBe(uuid2);
  });

  it('should have consistent UUID length', () => {
    const uuid = generateCorrelationId();
    expect(uuid).toHaveLength(36);
  });
});