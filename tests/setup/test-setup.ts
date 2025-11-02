/**
 * Per-Test Setup Configuration
 *
 * This file is imported before each test file and provides
 * common setup functionality for individual tests.
 */

import { vi, beforeEach, afterEach } from 'vitest';

// Setup global performance mock
if (typeof global.performance === 'undefined') {
  (global as any).performance = {
    now: () => Date.now(),
  };
}

// Setup global fail function for tests
if (typeof global.fail === 'undefined') {
  (global as any).fail = (message: string) => {
    throw new Error(message);
  };
}

// Common test utilities
export interface TestContext {
  mockServices: {
    database: any;
    embeddings: any;
    qdrant: any;
    logger: any;
  };
  testData: {
    sampleKnowledgeItems: any[];
    sampleEmbeddings: number[][];
  };
}

// Create test context
export const testContext: TestContext = {
  mockServices: {
    database: null,
    embeddings: null,
    qdrant: null,
    logger: null,
  },
  testData: {
    sampleKnowledgeItems: [],
    sampleEmbeddings: [],
  },
};

// Setup before each test
beforeEach(async () => {
  // Reset mocks
  vi.clearAllMocks();

  // Setup mock logger
  testContext.mockServices.logger = {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  };

  // Mock the logger module
  vi.doMock('../../src/utils/logger', () => ({
    logger: testContext.mockServices.logger,
  }));

  // Generate sample test data
  generateSampleTestData();

  // Setup service mocks
  await setupServiceMocks();
});

// Cleanup after each test
afterEach(() => {
  // Reset all mocks
  vi.restoreAllMocks();

  // Clear test context
  testContext.mockServices = {
    database: null,
    embeddings: null,
    qdrant: null,
    logger: null,
  };
});

/**
 * Generate sample test data
 */
function generateSampleTestData(): void {
  // Sample knowledge items for testing
  testContext.testData.sampleKnowledgeItems = [
    {
      id: 'test-entity-1',
      kind: 'entity',
      scope: { project: 'test-project', org: 'test-org' },
      data: {
        name: 'Test Entity 1',
        description: 'A test entity for unit testing',
        content: 'This is the content of test entity 1',
      },
      metadata: {
        created_at: new Date().toISOString(),
        test_data: true,
      },
    },
    {
      id: 'test-decision-1',
      kind: 'decision',
      scope: { project: 'test-project' },
      data: {
        title: 'Test Decision 1',
        context: 'Testing context',
        decision: 'We will use this approach',
        rationale: 'Because it makes sense for testing',
      },
      metadata: {
        created_at: new Date().toISOString(),
        test_data: true,
      },
    },
    {
      id: 'test-observation-1',
      kind: 'observation',
      scope: { project: 'test-project', branch: 'main' },
      data: {
        entity_type: 'test',
        entity_id: 'test-entity-1',
        observation: 'This is a test observation',
        value: 'test-value',
      },
      metadata: {
        created_at: new Date().toISOString(),
        test_data: true,
      },
    },
  ];

  // Sample embeddings for testing
  testContext.testData.sampleEmbeddings = [
    Array.from({ length: 1536 }, (_, i) => Math.sin(i * 0.1) * 0.5 + 0.5),
    Array.from({ length: 1536 }, (_, i) => Math.cos(i * 0.1) * 0.5 + 0.5),
    Array.from({ length: 1536 }, (_, i) => Math.sin(i * 0.2) * 0.3 + 0.7),
  ];
}

/**
 * Setup service mocks
 */
async function setupServiceMocks(): Promise<void> {
  // Mock database service
  testContext.mockServices.database = {
    store: vi.fn().mockResolvedValue({
      id: 'test-id',
      status: 'stored',
      created_at: new Date().toISOString(),
    }),
    find: vi.fn().mockResolvedValue([]),
    update: vi.fn().mockResolvedValue(true),
    delete: vi.fn().mockResolvedValue(true),
    healthCheck: vi.fn().mockResolvedValue(true),
  };

  // Mock embedding service
  testContext.mockServices.embeddings = {
    generateEmbedding: vi.fn().mockImplementation((text: string) => {
      const index =
        Math.abs(text.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0)) %
        testContext.testData.sampleEmbeddings.length;
      return Promise.resolve({
        vector: testContext.testData.sampleEmbeddings[index],
        dimensions: 1536,
        model: 'test-model',
      });
    }),
    generateBatchEmbeddings: vi.fn().mockImplementation((texts: string[]) => {
      return Promise.resolve({
        vectors: texts.map(
          (_, index) =>
            testContext.testData.sampleEmbeddings[
              index % testContext.testData.sampleEmbeddings.length
            ]
        ),
        dimensions: 1536,
        model: 'test-model',
      });
    }),
  };

  // Mock Qdrant client
  testContext.mockServices.qdrant = {
    upsert: vi.fn().mockResolvedValue({ status: 'completed' }),
    search: vi.fn().mockResolvedValue({ points: [] }),
    retrieve: vi.fn().mockResolvedValue([]),
    delete: vi.fn().mockResolvedValue({ status: 'completed' }),
    getCollections: vi.fn().mockResolvedValue({ collections: [] }),
    createCollection: vi.fn().mockResolvedValue(undefined),
    deleteCollection: vi.fn().mockResolvedValue(undefined),
  };

  // Apply mocks to modules
  vi.doMock('../../src/db/unified-database-layer-v2', () => ({
    UnifiedDatabaseLayerV2: vi.fn().mockImplementation(() => testContext.mockServices.database),
  }));

  vi.doMock('../../src/services/embeddings/embedding-service', () => ({
    EmbeddingService: vi.fn().mockImplementation(() => testContext.mockServices.embeddings),
  }));

  vi.doMock('../../src/db/qdrant-client', () => ({
    qdrant: testContext.mockServices.qdrant,
  }));
}

/**
 * Common test helpers
 */
export const testHelpers = {
  /**
   * Create a mock knowledge item
   */
  createMockKnowledgeItem: (overrides: any = {}) => ({
    id: 'test-id',
    kind: 'entity',
    scope: { project: 'test' },
    data: { content: 'test content' },
    metadata: {},
    ...overrides,
  }),

  /**
   * Wait for async operations
   */
  wait: (ms: number = 100) => new Promise((resolve) => setTimeout(resolve, ms)),

  /**
   * Create a mock error
   */
  createMockError: (message: string, code: string = 'TEST_ERROR') => {
    const error = new Error(message) as any;
    error.code = code;
    error.timestamp = new Date().toISOString();
    return error;
  },

  /**
   * Assert that a function was called with specific arguments
   */
  assertCalledWith: (fn: any, args: any[]) => {
    expect(fn).toHaveBeenCalledWith(...args);
  },

  /**
   * Create test embeddings for given text
   */
  createTestEmbedding: (text: string) => {
    const index =
      Math.abs(text.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0)) %
      testContext.testData.sampleEmbeddings.length;
    return testContext.testData.sampleEmbeddings[index];
  },
};

// Export for use in test files
export { vi, beforeEach, afterEach };
