/**
 * Test Setup for Cortex Memory MCP
 *
 * This file sets up the test environment for Vitest tests.
 * It configures global test utilities and mocks.
 */

import { vi } from 'vitest';

// Mock console methods to reduce noise in tests
global.console = {
  ...console,
  // Uncomment to ignore specific console methods in tests
  // log: vi.fn(),
  // debug: vi.fn(),
  // info: vi.fn(),
  // warn: vi.fn(),
  // error: vi.fn(),
};

// Set up global test timeout
vi.setConfig({ testTimeout: 30000 });

// Mock environment variables for testing
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error';

// Global test utilities
declare global {
  namespace Vi {
    interface JestAssertion<T = any> {
      toBeValidKnowledgeItem(): T;
      toHaveValidScope(): T;
      toHaveValidTimestamp(): T;
    }
  }
}

// Custom matchers for test assertions
const customMatchers = {
  toBeValidKnowledgeItem(received: any) {
    const hasKind = received && typeof received.kind === 'string';
    const hasScope = received && typeof received.scope === 'object';
    const hasData = received && typeof received.data === 'object';

    const pass = hasKind && hasScope && hasData;

    if (pass) {
      return {
        message: () => `expected ${received} not to be a valid knowledge item`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be a valid knowledge item with kind, scope, and data`,
        pass: false,
      };
    }
  },

  toHaveValidScope(received: any) {
    const hasScope = received && received.scope;
    const hasProject = hasScope && typeof received.scope.project === 'string';
    const hasBranch = hasScope && typeof received.scope.branch === 'string';

    const pass = hasProject && hasBranch;

    if (pass) {
      return {
        message: () => `expected ${received} not to have a valid scope`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to have a valid scope with project and branch`,
        pass: false,
      };
    }
  },

  toHaveValidTimestamp(received: any) {
    const hasTimestamp = received && received.data && received.data.timestamp;
    const isValidTimestamp = hasTimestamp && typeof received.data.timestamp === 'string';

    const pass = isValidTimestamp;

    if (pass) {
      return {
        message: () => `expected ${received} not to have a valid timestamp`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to have a valid timestamp in data.timestamp`,
        pass: false,
      };
    }
  },
};

// Extend Vitest's expect with custom matchers
expect.extend(customMatchers);

// Test data factory for common test scenarios
export const createTestKnowledgeItem = (overrides: any = {}) => ({
  kind: 'section',
  scope: {
    project: 'test-project',
    branch: 'main',
    org: 'test-org',
  },
  data: {
    title: 'Test Section',
    content: 'This is a test section for unit testing.',
    timestamp: new Date().toISOString(),
    ...overrides,
  },
});

// Mock Prisma client for unit tests
export const mockPrismaClient = {
  section: { create: vi.fn(), findMany: vi.fn(), update: vi.fn(), delete: vi.fn() },
  adrDecision: { create: vi.fn(), findMany: vi.fn(), update: vi.fn(), delete: vi.fn() },
  issueLog: { create: vi.fn(), findMany: vi.fn(), update: vi.fn(), delete: vi.fn() },
  todoLog: { create: vi.fn(), findMany: vi.fn(), update: vi.fn(), delete: vi.fn() },
  // ... add more as needed
  $connect: vi.fn(),
  $disconnect: vi.fn(),
  $transaction: vi.fn(),
};

// Test utility functions
export const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

export const createMockLogger = () => ({
  info: vi.fn(),
  debug: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  fatal: vi.fn(),
});

export const createMockResponse = (data: any, status = 200) => ({
  success: true,
  data,
  status,
  timestamp: new Date().toISOString(),
});

// Setup and teardown hooks
beforeAll(async () => {
  // Global setup before all tests
  console.log('🧪 Test suite starting...');
});

afterAll(async () => {
  // Global cleanup after all tests
  console.log('✅ Test suite completed');
});

beforeEach(async () => {
  // Setup before each test
  vi.clearAllMocks();
});

afterEach(async () => {
  // Cleanup after each test
  vi.restoreAllMocks();
});