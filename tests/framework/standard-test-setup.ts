/**
 * Standardized Test Setup Templates
 *
 * Provides consistent test setup, teardown, and mock management patterns
 * for all test types in the Cortex Memory MCP project.
 */

import { vi, beforeEach, afterEach, beforeAll, afterAll } from 'vitest';
import { config } from 'dotenv';

// Load test environment
config({ path: '.env.test' });

// Standard test environment configuration
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error';
process.env.QDRANT_COLLECTION_NAME = 'test-cortex-memory';

/**
 * Mock cleanup tracker
 */
class MockTracker {
  private mocks: Map<string, any> = new Map();

  registerMock(name: string, mock: any): void {
    this.mocks.set(name, mock);
  }

  clearAllMocks(): void {
    this.mocks.forEach(mock => {
      if (mock && typeof mock.mockClear === 'function') {
        mock.mockClear();
      }
      if (mock && typeof mock.mockReset === 'function') {
        mock.mockReset();
      }
    });
    this.mocks.clear();
  }

  restoreAllMocks(): void {
    this.mocks.forEach(mock => {
      if (mock && typeof mock.mockRestore === 'function') {
        mock.mockRestore();
      }
    });
    this.mocks.clear();
  }
}

/**
 * Standard test utilities
 */
export class StandardTestUtils {
  private static mockTracker = new MockTracker();
  private static originalConsole = { ...console };

  /**
   * Standard test environment setup
   */
  static setupTestEnvironment(): void {
    // Mock console methods to reduce noise
    console.error = vi.fn();
    console.warn = vi.fn();
    console.info = vi.fn();
    console.debug = vi.fn();
    console.log = vi.fn();
  }

  /**
   * Standard test environment cleanup
   */
  static cleanupTestEnvironment(): void {
    // Restore console methods
    Object.assign(console, StandardTestUtils.originalConsole);

    // Clear all mocks
    StandardTestUtils.mockTracker.restoreAllMocks();
    vi.clearAllMocks();
  }

  /**
   * Register a mock for cleanup tracking
   */
  static registerMock(name: string, mock: any): void {
    this.mockTracker.registerMock(name, mock);
  }

  /**
   * Create a standardized mock object
   */
  static createMock<T = any>(implementation?: Partial<T>): vi.Mocked<T> {
    const mock = vi.fn() as any;
    if (implementation) {
      Object.assign(mock, implementation);
    }
    return mock;
  }

  /**
   * Generate test data with consistent patterns
   */
  static generateTestData(overrides: Record<string, unknown> = {}) {
    return {
      id: `test-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      test: true,
      ...overrides,
    };
  }

  /**
   * Generate test scope
   */
  static generateTestScope(overrides: Record<string, unknown> = {}) {
    return {
      project: 'test-project',
      branch: 'test-branch',
      org: 'test-org',
      ...overrides,
    };
  }

  /**
   * Generate test metadata
   */
  static generateTestMetadata(overrides: Record<string, unknown> = {}) {
    return {
      test: true,
      test_run: Date.now(),
      ...overrides,
    };
  }

  /**
   * Create standard test context
   */
  static createTestContext(overrides: Record<string, unknown> = {}) {
    return {
      testId: `test-${Date.now()}`,
      startTime: Date.now(),
      utils: StandardTestUtils,
      ...overrides,
    };
  }

  /**
   * Standard performance measurement
   */
  static async measurePerformance<T>(
    operation: () => Promise<T>,
    maxDuration: number = 1000
  ): Promise<{ result: T; duration: number }> {
    const start = Date.now();
    const result = await operation();
    const duration = Date.now() - start;

    if (duration > maxDuration) {
      throw new Error(`Performance threshold exceeded: ${duration}ms > ${maxDuration}ms`);
    }

    return { result, duration };
  }

  /**
   * Standard async timeout wrapper
   */
  static withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number = 5000
  ): Promise<T> {
    return Promise.race([
      promise,
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(`Operation timed out after ${timeoutMs}ms`)), timeoutMs)
      ),
    ]);
  }
}

/**
 * Mock factory for common dependencies
 */
export class MockFactory {
  /**
   * Create mock Qdrant client
   */
  static createQdrantClient() {
    const mock = {
      getCollections: vi.fn().mockResolvedValue({
        collections: [{ name: 'test-collection', points_count: 0 }]
      }),
      createCollection: vi.fn().mockResolvedValue(undefined),
      deleteCollection: vi.fn().mockResolvedValue(undefined),
      upsert: vi.fn().mockResolvedValue({ status: 'completed' }),
      search: vi.fn().mockResolvedValue([]),
      getCollection: vi.fn().mockResolvedValue({
        points_count: 0,
        status: 'green',
        optimizer_status: 'ok'
      }),
      delete: vi.fn().mockResolvedValue({ status: 'completed' }),
      scroll: vi.fn().mockResolvedValue({
        points: [],
        next_page_offset: null
      }),
      count: vi.fn().mockResolvedValue({ count: 0 }),
      healthCheck: vi.fn().mockResolvedValue(true)
    };

    StandardTestUtils.registerMock('qdrantClient', mock);
    return mock;
  }

  /**
   * Create mock authentication service
   */
  static createAuthService() {
    const mock = {
      hashPassword: vi.fn().mockResolvedValue('hashed-password'),
      comparePassword: vi.fn().mockResolvedValue(true),
      generateToken: vi.fn().mockReturnValue('mock-jwt-token'),
      verifyToken: vi.fn().mockResolvedValue({ userId: 'test-user', role: 'user' }),
      refreshToken: vi.fn().mockReturnValue('mock-refresh-token'),
      invalidateToken: vi.fn().mockResolvedValue(true),
      createSession: vi.fn().mockResolvedValue({ sessionId: 'test-session' }),
      validateSession: vi.fn().mockResolvedValue(true),
      destroySession: vi.fn().mockResolvedValue(true)
    };

    StandardTestUtils.registerMock('authService', mock);
    return mock;
  }

  /**
   * Create mock audit service
   */
  static createAuditService() {
    const mock = {
      logEvent: vi.fn().mockResolvedValue(undefined),
      logAuthEvent: vi.fn().mockResolvedValue(undefined),
      logDataEvent: vi.fn().mockResolvedValue(undefined),
      logSecurityEvent: vi.fn().mockResolvedValue(undefined),
      getAuditLog: vi.fn().mockResolvedValue([]),
      searchAuditLog: vi.fn().mockResolvedValue([]),
      exportAuditLog: vi.fn().mockResolvedValue({ data: [], totalCount: 0 })
    };

    StandardTestUtils.registerMock('auditService', mock);
    return mock;
  }

  /**
   * Create mock embedding service
   */
  static createEmbeddingService() {
    const mock = {
      generateEmbedding: vi.fn().mockResolvedValue([0.1, 0.2, 0.3, 0.4, 0.5]),
      generateBatchEmbeddings: vi.fn().mockResolvedValue([
        [0.1, 0.2, 0.3, 0.4, 0.5],
        [0.6, 0.7, 0.8, 0.9, 1.0]
      ]),
      calculateSimilarity: vi.fn().mockReturnValue(0.85),
      findMostSimilar: vi.fn().mockResolvedValue({ id: 'test-item', score: 0.9 })
    };

    StandardTestUtils.registerMock('embeddingService', mock);
    return mock;
  }
}

/**
 * Standard test patterns for different test types
 */
export class TestPatterns {
  /**
   * Unit test pattern - isolated testing of single components
   */
  static unitTest(setupFn?: () => void | Promise<void>, teardownFn?: () => void | Promise<void>) {
    beforeEach(async () => {
      StandardTestUtils.setupTestEnvironment();
      if (setupFn) await setupFn();
    });

    afterEach(async () => {
      if (teardownFn) await teardownFn();
      StandardTestUtils.cleanupTestEnvironment();
    });
  }

  /**
   * Integration test pattern - testing component interactions
   */
  static integrationTest(setupFn?: () => void | Promise<void>, teardownFn?: () => void | Promise<void>) {
    beforeAll(async () => {
      StandardTestUtils.setupTestEnvironment();
      if (setupFn) await setupFn();
    });

    afterAll(async () => {
      if (teardownFn) await teardownFn();
      StandardTestUtils.cleanupTestEnvironment();
    });

    beforeEach(() => {
      // Clear mocks between tests but keep setup
      vi.clearAllMocks();
    });
  }

  /**
   * Performance test pattern - with performance validation
   */
  static performanceTest(maxDuration: number = 1000) {
    beforeEach(() => {
      StandardTestUtils.setupTestEnvironment();
    });

    afterEach(() => {
      StandardTestUtils.cleanupTestEnvironment();
    });

    return (testFn: () => Promise<void>) => async () => {
      const { duration } = await StandardTestUtils.measurePerformance(testFn, maxDuration);
      expect(duration).toBeLessThan(maxDuration);
    };
  }

  /**
   * Security test pattern - with security validation
   */
  static securityTest() {
    beforeEach(() => {
      StandardTestUtils.setupTestEnvironment();
    });

    afterEach(() => {
      StandardTestUtils.cleanupTestEnvironment();
    });

    return (testFn: () => Promise<void>) => async () => {
      // Security tests should never leak sensitive information
      const originalConsoleError = console.error;
      console.error = vi.fn();

      try {
        await testFn();

        // Verify no sensitive data was logged
        const errorCalls = (console.error as any).mock.calls;
        const sensitiveDataPatterns = [
          /password/i,
          /secret/i,
          /token/i,
          /key/i,
          /auth/i
        ];

        for (const call of errorCalls) {
          const message = call.join(' ');
          for (const pattern of sensitiveDataPatterns) {
            expect(message).not.toMatch(pattern);
          }
        }
      } finally {
        console.error = originalConsoleError;
      }
    };
  }
}

/**
 * Global test setup for all tests
 */
beforeAll(() => {
  StandardTestUtils.setupTestEnvironment();
});

afterAll(() => {
  StandardTestUtils.cleanupTestEnvironment();
});

// Export commonly used patterns
export { beforeEach, afterEach, beforeAll, afterAll, describe, it, expect, vi } from 'vitest';
export { StandardTestUtils as TestUtils, MockFactory, TestPatterns };

// Type definitions for better test development
export interface TestContext {
  testId: string;
  startTime: number;
  utils: typeof StandardTestUtils;
  mocks: {
    qdrant?: any;
    auth?: any;
    audit?: any;
    embedding?: any;
  };
}

export interface MockConfig {
  clearMocks?: boolean;
  restoreMocks?: boolean;
  timeout?: number;
}

// Default test configuration
export const DEFAULT_TEST_CONFIG: Required<MockConfig> = {
  clearMocks: true,
  restoreMocks: true,
  timeout: 5000,
};