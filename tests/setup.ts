import { config } from 'dotenv';
import { vi } from 'vitest';

// Load test environment variables
config({ path: '.env.test' });

// Import Windows-specific test setup for Windows environments
if (process.platform === 'win32') {
  await import('./setup/windows-test-setup.js');
}

// Set test environment variables
process.env['NODE_ENV'] = 'test';
process.env['LOG_LEVEL'] = 'error'; // Minimize logs during testing
process.env['QDRANT_COLLECTION_NAME'] = 'test-cortex-memory';

// Mock VectorDatabase for tests that expect it
(global as any).VectorDatabase = class MockVectorDatabase {
  client: any;

  constructor() {
    this.client = {
      getCollections: vi.fn().mockResolvedValue({
        collections: [{ name: 'test-collection' }],
      }),
      createCollection: vi.fn().mockResolvedValue(undefined),
      upsert: vi.fn().mockResolvedValue(undefined),
      search: vi.fn().mockResolvedValue([]),
      getCollection: vi.fn().mockResolvedValue({
        points_count: 0,
        status: 'green',
        optimizer_status: { ok: true },
      }),
      delete: vi.fn().mockResolvedValue(undefined),
      scroll: vi.fn().mockResolvedValue({
        points: [],
        total_pages: 0,
      }),
    };
  }
};

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
