/**
 * Jest/Vitest Global Test Setup
 *
 * Provides global test utilities, mocks, and configuration for all test suites.
 * This file sets up the testing environment with proper mocking, utilities,
 * and global helpers for consistent test behavior across the project.
 */

import { vi } from 'vitest';
import { QdrantTestDouble, createPerfectQdrantTestDouble } from '../helpers/qdrant-test-double.js';

// Global test configuration
global.testConfig = {
  // Default timeout for async operations
  timeout: 30000,

  // Test data configuration
  maxTestItems: 100,

  // Performance thresholds
  performance: {
    maxResponseTime: 5000,
    maxMemoryUsage: 100 * 1024 * 1024, // 100MB
    maxCpuUsage: 80, // percentage
  },

  // Retry configuration for flaky tests
  retry: {
    maxAttempts: 3,
    delay: 1000,
  },
};

// Global test state
global.testState = {
  // Track test execution
  currentTest: null,
  testStartTime: null,

  // Resource tracking
  fileHandles: 0,
  memoryUsage: 0,

  // Mock instances
  qdrantTestDouble: null,

  // Test data
  testData: new Map(),
};

// Global test utilities
global.testUtils = {
  /**
   * Create a test timer with configurable delay
   */
  async delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  },

  /**
   * Measure execution time of an async function
   */
  async measureTime<T>(fn: () => Promise<T>): Promise<{ result: T; time: number }> {
    const start = Date.now();
    const result = await fn();
    const time = Date.now() - start;
    return { result, time };
  },

  /**
   * Generate random test data
   */
  generateRandomString(length: number = 10): string {
    return Math.random()
      .toString(36)
      .substring(2, 2 + length);
  },

  generateRandomEmail(): string {
    const domains = ['test.com', 'example.org', 'demo.net'];
    const domain = domains[Math.floor(Math.random() * domains.length)];
    const username = this.generateRandomString(8);
    return `${username}@${domain}`;
  },

  generateRandomId(): string {
    return `test-${Date.now()}-${this.generateRandomString(6)}`;
  },

  /**
   * Create test knowledge item
   */
  createTestKnowledgeItem(overrides: any = {}) {
    const baseId = this.generateRandomId();
    return {
      id: baseId,
      kind: 'entity',
      scope: { project: 'test-project', org: 'test-org' },
      data: {
        content: `Test content for ${baseId}`,
        name: `Test Item ${baseId}`,
        created_at: new Date().toISOString(),
      },
      metadata: {
        test_data: true,
        created_at: new Date().toISOString(),
      },
      ...overrides,
    };
  },

  /**
   * Create test knowledge items in bulk
   */
  createTestKnowledgeItems(count: number, overrides: any = {}): any[] {
    return Array.from({ length: count }, () => this.createTestKnowledgeItem(overrides));
  },

  /**
   * Validate knowledge item structure
   */
  validateKnowledgeItem(item: any): boolean {
    return (
      typeof item.id === 'string' &&
      typeof item.kind === 'string' &&
      typeof item.scope === 'object' &&
      typeof item.data === 'object' &&
      item.created_at !== undefined
    );
  },

  /**
   * Deep clone objects for test isolation
   */
  deepClone<T>(obj: T): T {
    return JSON.parse(JSON.stringify(obj));
  },

  /**
   * Wait for condition to be true with timeout
   */
  async waitForCondition(
    condition: () => boolean | Promise<boolean>,
    timeout: number = 5000,
    interval: number = 100
  ): Promise<void> {
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      if (await condition()) {
        return;
      }
      await this.delay(interval);
    }

    throw new Error(`Condition not met within ${timeout}ms`);
  },
};

// Global mock setup
global.setupGlobalMocks = () => {
  // Mock console methods to reduce noise in tests
  global.console = {
    ...console,
    log: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  };

  // Mock process.env for consistent test environment
  process.env['NODE_ENV'] = 'test';
  process.env['QDRANT_URL'] = process.env['QDRANT_URL'] || 'http://localhost:6333';
  process.env['LOG_LEVEL'] = 'error'; // Reduce log noise in tests

  // Create global Qdrant test double
  global.testState.qdrantTestDouble = createPerfectQdrantTestDouble();
};

// Global cleanup
global.cleanupGlobalState = () => {
  // Reset test state
  global.testState.currentTest = null;
  global.testState.testStartTime = null;
  global.testState.fileHandles = 0;
  global.testState.memoryUsage = 0;
  global.testState.testData.clear();

  // Reset mocks
  vi.clearAllMocks();

  // Reset Qdrant test double
  if (global.testState.qdrantTestDouble) {
    global.testState.qdrantTestDouble.reset();
  }
};

// Performance monitoring utilities
global.performanceUtils = {
  /**
   * Get current memory usage
   */
  getMemoryUsage(): any {
    if (typeof process !== 'undefined' && process.memoryUsage) {
      return process.memoryUsage();
    }
    return null;
  },

  /**
   * Assert performance thresholds
   */
  assertPerformance(responseTime: number, operation: string): void {
    expect(responseTime).toBeLessThan(global.testConfig.performance.maxResponseTime);
  },

  /**
   * Monitor memory usage during test
   */
  async monitorMemoryUsage<T>(
    fn: () => Promise<T>
  ): Promise<{ result: T; memoryBefore: any; memoryAfter: any; delta: any }> {
    const memoryBefore = this.getMemoryUsage();
    const result = await fn();
    const memoryAfter = this.getMemoryUsage();

    let delta = null;
    if (memoryBefore && memoryAfter) {
      delta = {
        rss: memoryAfter.rss - memoryBefore.rss,
        heapUsed: memoryAfter.heapUsed - memoryBefore.heapUsed,
        heapTotal: memoryAfter.heapTotal - memoryBefore.heapTotal,
      };
    }

    return { result, memoryBefore, memoryAfter, delta };
  },
};

// Error handling utilities
global.errorUtils = {
  /**
   * Assert error type and message
   */
  assertError(error: any, expectedType: string, expectedMessage?: string): void {
    expect(error).toBeInstanceOf(Error);

    if (expectedType && error.constructor.name !== expectedType) {
      throw new Error(`Expected error type ${expectedType}, got ${error.constructor.name}`);
    }

    if (expectedMessage && !error.message.includes(expectedMessage)) {
      throw new Error(
        `Expected error message to contain "${expectedMessage}", got "${error.message}"`
      );
    }
  },

  /**
   * Create test error with specific properties
   */
  createTestError(message: string, type: string = 'Error', code?: string): Error {
    const error = new Error(message);
    (error as any).name = type;
    if (code) {
      (error as any).code = code;
    }
    return error;
  },
};

// Async testing utilities
global.asyncUtils = {
  /**
   * Run async operations with timeout
   */
  async withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number = global.testConfig.timeout
  ): Promise<T> {
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error(`Operation timed out after ${timeoutMs}ms`)), timeoutMs);
    });

    return Promise.race([promise, timeoutPromise]);
  },

  /**
   * Retry async operations
   */
  async retry<T>(
    fn: () => Promise<T>,
    maxAttempts: number = global.testConfig.retry.maxAttempts,
    delay: number = global.testConfig.retry.delay
  ): Promise<T> {
    let lastError: Error;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error as Error;

        if (attempt === maxAttempts) {
          throw lastError;
        }

        await testUtils.delay(delay);
      }
    }

    throw lastError!;
  },
};

// Setup global mocks
global.setupGlobalMocks();

// Global test hooks
beforeEach(() => {
  global.testState.testStartTime = Date.now();
  global.testState.currentTest = expect.getState().currentTestName;
});

afterEach(() => {
  const testDuration = Date.now() - (global.testState.testStartTime || 0);

  // Log test performance if it exceeds threshold
  if (testDuration > global.testConfig.performance.maxResponseTime) {
    console.warn(
      `Test "${global.testState.currentTest}" took ${testDuration}ms (threshold: ${global.testConfig.performance.maxResponseTime}ms)`
    );
  }
});

// Export types for TypeScript support
declare global {
  var testConfig: {
    timeout: number;
    maxTestItems: number;
    performance: {
      maxResponseTime: number;
      maxMemoryUsage: number;
      maxCpuUsage: number;
    };
    retry: {
      maxAttempts: number;
      delay: number;
    };
  };

  var testState: {
    currentTest: string | null;
    testStartTime: number | null;
    fileHandles: number;
    memoryUsage: number;
    qdrantTestDouble: QdrantTestDouble | null;
    testData: Map<string, any>;
  };

  var testUtils: {
    delay: (ms: number) => Promise<void>;
    measureTime: <T>(fn: () => Promise<T>) => Promise<{ result: T; time: number }>;
    generateRandomString: (length?: number) => string;
    generateRandomEmail: () => string;
    generateRandomId: () => string;
    createTestKnowledgeItem: (overrides?: any) => any;
    createTestKnowledgeItems: (count: number, overrides?: any) => any[];
    validateKnowledgeItem: (item: any) => boolean;
    deepClone: <T>(obj: T) => T;
    waitForCondition: (
      condition: () => boolean | Promise<boolean>,
      timeout?: number,
      interval?: number
    ) => Promise<void>;
  };

  var performanceUtils: {
    getMemoryUsage: () => any;
    assertPerformance: (responseTime: number, operation: string) => void;
    monitorMemoryUsage: <T>(
      fn: () => Promise<T>
    ) => Promise<{ result: T; memoryBefore: any; memoryAfter: any; delta: any }>;
  };

  var errorUtils: {
    assertError: (error: any, expectedType: string, expectedMessage?: string) => void;
    createTestError: (message: string, type?: string, code?: string) => Error;
  };

  var asyncUtils: {
    withTimeout: <T>(promise: Promise<T>, timeoutMs?: number) => Promise<T>;
    retry: <T>(fn: () => Promise<T>, maxAttempts?: number, delay?: number) => Promise<T>;
  };

  var setupGlobalMocks: () => void;
  var cleanupGlobalState: () => void;
}

export { QdrantTestDouble, createPerfectQdrantTestDouble };
