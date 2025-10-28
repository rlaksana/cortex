import { config } from 'dotenv';

// Load test environment variables
config({ path: '.env.test' });

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error'; // Minimize logs during testing
process.env.QDRANT_COLLECTION_NAME = 'test-cortex-memory';

// Global test utilities
global.testUtils = {
  generateTestItem: (overrides: any = {}) => ({
    kind: 'entity',
    content: 'Test content',
    metadata: { test: true },
    scope: { project: 'test-project' },
    ...overrides,
  }),

  generateBatchItems: (count: number, overrides: any = {}) =>
    Array.from({ length: count }, (_, i) => ({
      kind: 'entity',
      content: `Test item ${i}`,
      metadata: { batch: true, index: i },
      ...overrides,
    })),
};

// Mock console methods to reduce noise during tests
const originalConsole = { ...console };
import { vi } from 'vitest';

beforeAll(() => {
  console.error = vi.fn();
  console.warn = vi.fn();
  console.info = vi.fn();
  console.debug = vi.fn();
});

afterAll(() => {
  // Restore original console methods
  Object.assign(console, originalConsole);
});
