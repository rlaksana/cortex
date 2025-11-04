import { config } from 'dotenv';

// Load test environment variables
config({ path: '.env.test' });

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error'; // Minimize logs during testing
process.env.QDRANT_COLLECTION_NAME = 'test-cortex-memory';

// Import comprehensive test setup
import './setup/jest-setup.js';

// Additional simple test utilities for backward compatibility
global.testUtils = {
  // Legacy utilities for existing tests
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

  // Reference to comprehensive utilities
  ...global.testUtils,
};
