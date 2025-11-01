/**
 * Mock Setup Extension for MCP Cortex Tests
 *
 * This file extends the basic test setup with comprehensive mock templates.
 * Import this file in your test files to access the mock utilities.
 */

import { vi, beforeEach, afterEach } from 'vitest';
import { createMockTestEnvironment, createMockEnvironment, MockDataGenerators } from './utils/mock-templates';

// Set additional test environment variables
process.env.MOCK_EXTERNAL_SERVICES = 'true';

// Enhance global test utils with mock templates
global.testUtils = {
  ...global.testUtils, // Preserve existing utilities from setup.ts

  // New mock templates
  createMockEnvironment,
  createMockTestEnvironment,
  MockDataGenerators,

  // Helper to create mock environment with test defaults
  createTestEnvironment: (overrides = {}) =>
    createMockEnvironment({
      NODE_ENV: 'test',
      LOG_LEVEL: 'error',
      MOCK_EXTERNAL_SERVICES: true,
      ...overrides,
    }),

  // Helper to wait for async operations in tests
  waitFor: (ms = 0) => new Promise(resolve => setTimeout(resolve, ms)),

  // Helper to create fake timers for time-dependent tests
  useFakeTimers: () => {
    vi.useFakeTimers();
    return {
      advanceTimeBy: (ms: number) => vi.advanceTimersByTime(ms),
      advanceTimeTo: (date: Date) => vi.advanceTimersToTime(date.getTime()),
      runAllTimers: () => vi.runAllTimers(),
      runOnlyPendingTimers: () => vi.runOnlyPendingTimers(),
    };
  },

  // Common mock patterns
  mocks: {
    createSuccessfulQdrantClient: () =>
      createMockTestEnvironment().qdrantClient,
    createFailingQdrantClient: (failMethods = ['search']) =>
      createMockTestEnvironment({
        qdrant: { shouldFail: true, failMethods }
      }).qdrantClient,
    createMockAuthService: (overrides = {}) =>
      createMockTestEnvironment({ auth: overrides }).authService,
    createMockLogger: () => createMockTestEnvironment().logger,
    createMockDatabaseAdapter: (overrides = {}) =>
      createMockTestEnvironment({ database: overrides }).databaseAdapter,
    createMockMemoryStore: (overrides = {}) =>
      createMockTestEnvironment({ memoryStore: overrides }).memoryStore,
    createMockEmbeddingService: (overrides = {}) =>
      createMockTestEnvironment({ embedding: overrides }).embeddingService,
  },

  // Test helpers for common scenarios
  scenarios: {
    // Successful memory operations
    successfulMemoryStore: () => createMockTestEnvironment({
      qdrant: { healthStatus: true },
      database: { connectionStatus: 'connected' },
      memoryStore: { shouldFail: false },
    }),

    // Failing Qdrant client
    failingQdrant: (failMethods = ['search', 'upsert']) => createMockTestEnvironment({
      qdrant: { shouldFail: true, failMethods },
      database: { connectionStatus: 'error' },
    }),

    // Authentication failures
    authFailure: () => createMockTestEnvironment({
      auth: {
        shouldFail: true,
        failOperations: ['validateUserWithDatabase', 'validateApiKeyWithDatabase'],
      },
    }),

    // Network latency simulation
    highLatency: (ms = 100) => createMockTestEnvironment({
      qdrant: { searchResults: [], latency: ms },
      database: { latency: ms },
    }),
  },

  // Assertion helpers
  expect: {
    toHaveBeenCalledWithValidUser: (mock) => {
      expect(mock).toHaveBeenCalledWith(
        expect.objectContaining({
          username: expect.any(String),
          password: expect.any(String),
        })
      );
    },

    toHaveBeenCalledWithValidQuery: (mock) => {
      expect(mock).toHaveBeenCalledWith(
        expect.objectContaining({
          query: expect.any(String),
          limit: expect.any(Number),
        })
      );
    },

    toHaveBeenCalledWithKnowledgeItem: (mock) => {
      expect(mock).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: expect.any(String),
          content: expect.any(String),
          scope: expect.any(Object),
        })
      );
    },
  },
};

// Test isolation - run before each test
beforeEach(() => {
  // Clear all mocks before each test
  vi.clearAllMocks();
});

// Cleanup after each test
afterEach(() => {
  // Clear any timers
  vi.clearAllTimers();
  // Reset fake timers
  vi.useRealTimers();
});

// Export for convenience in test files
export {
  createMockEnvironment,
  createMockTestEnvironment,
  MockDataGenerators,
};

export default global.testUtils;