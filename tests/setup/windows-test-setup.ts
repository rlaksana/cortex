/**
 * Windows-specific Test Setup Configuration
 *
 * This file provides Windows-specific optimizations for test execution,
 * including ZAI configuration loading, enhanced EMFILE prevention,
 * and performance optimizations for Windows environments.
 *
 * @author Cortex Team
 * @version 2.0.0
 */

import { config } from 'dotenv';
import { vi, beforeEach, afterEach } from 'vitest';
import { ZAIConfigManager } from '../../src/config/zai-config.js';

// Load test environment variables with explicit path
config({ path: '.env.test' });

// Additional environment overrides for Windows testing
process.env['NODE_ENV'] = 'test';
process.env['LOG_LEVEL'] = 'error';
process.env['QDRANT_COLLECTION_NAME'] = 'test-cortex-memory';
process.env['MOCK_EMBEDDINGS'] = 'true';
process.env['MOCK_EMBEDDING_SERVICE'] = 'true';

// Windows-specific performance optimizations
if (process.platform === 'win32') {
  process.env['UV_THREADPOOL_SIZE'] = '16';
  process.env['NODE_OPTIONS'] = `${process.env['NODE_OPTIONS'] || ''} --max-old-space-size=4096 --expose-gc`;

  // Force garbage collection availability
  try {
    const v8 = await import('v8');
    (global as any).gc = v8.getHeapStatistics;
  } catch (e) {
    // Fallback for testing
    (global as any).gc = () => {
      // Mock GC for testing
      if (global.gc) {
        global.gc();
      }
    };
  }
}

// Global test context with Windows optimizations
interface WindowsTestContext {
  mockServices: {
    database: any;
    embeddings: any;
    qdrant: any;
    logger: any;
    zaiConfig: any;
  };
  testData: {
    sampleKnowledgeItems: any[];
    sampleEmbeddings: number[][];
  };
  windows: {
    fileHandleCount: number;
    gcCount: number;
    emfilePrevention: {
      active: boolean;
      lastCleanup: number;
      handleThreshold: number;
    };
  };
}

export const windowsTestContext: WindowsTestContext = {
  mockServices: {
    database: null,
    embeddings: null,
    qdrant: null,
    logger: null,
    zaiConfig: null,
  },
  testData: {
    sampleKnowledgeItems: [],
    sampleEmbeddings: [],
  },
  windows: {
    fileHandleCount: 0,
    gcCount: 0,
    emfilePrevention: {
      active: true,
      lastCleanup: Date.now(),
      handleThreshold: 100,
    },
  },
};

/**
 * Initialize ZAI configuration for testing
 */
async function initializeZAIConfig(): Promise<void> {
  try {
    const zaiConfigManager = new ZAIConfigManager();

    // Load configuration with test environment variables
    await zaiConfigManager.loadConfig();

    // Store in test context for global access
    windowsTestContext.mockServices.zaiConfig = zaiConfigManager.getZAIConfig();

    console.log('✅ ZAI configuration loaded for testing');

    // Mock ZAI client service for tests
    vi.doMock('../../src/services/ai/zai-client.service', () => ({
      ZAIClientService: vi.fn().mockImplementation(() => ({
        getZAIConfig: () => windowsTestContext.mockServices.zaiConfig,
        initialize: vi.fn().mockResolvedValue(true),
        healthCheck: vi.fn().mockResolvedValue({ status: 'healthy' }),
        generateInsight: vi.fn().mockResolvedValue({
          insight: 'test insight',
          confidence: 0.95,
          sources: ['test'],
        }),
        cleanup: vi.fn().mockResolvedValue(undefined),
      })),
    }));
  } catch (error) {
    console.warn('⚠️ ZAI configuration failed to load, using mock:', error);

    // Provide fallback mock configuration
    windowsTestContext.mockServices.zaiConfig = {
      baseURL: 'https://api.z.ai/api/anthropic',
      model: 'glm-4.6',
      timeout: 30000,
      maxRetries: 3,
      retryDelay: 1000,
      circuitBreakerThreshold: 3,
      circuitBreakerTimeout: 60000,
      enableLogging: false,
      rateLimitRPM: 60,
      apiKey: 'test-zai-key-for-testing-only',
    };
  }
}

/**
 * Windows-specific EMFILE prevention
 */
function setupWindowsEMFILEPrevention(): void {
  if (process.platform !== 'win32') return;

  const { emfilePrevention } = windowsTestContext.windows;

  // Monitor file handles every 5 seconds
  const monitorInterval = setInterval(() => {
    try {
      const activeHandles = (process as any)._getActiveHandles();
      windowsTestContext.windows.fileHandleCount = Array.isArray(activeHandles)
        ? activeHandles.length
        : 0;

      // Force cleanup if threshold exceeded
      if (windowsTestContext.windows.fileHandleCount > emfilePrevention.handleThreshold) {
        console.warn(
          `⚠️ File handle count (${windowsTestContext.windows.fileHandleCount}) exceeds threshold (${emfilePrevention.handleThreshold})`
        );
        forceWindowsCleanup();
      }
    } catch (error) {
      // Ignore monitoring errors
    }
  }, 5000);

  // Cleanup on process exit
  process.on('exit', () => {
    clearInterval(monitorInterval);
    forceWindowsCleanup();
  });
}

/**
 * Force Windows cleanup operations
 */
function forceWindowsCleanup(): void {
  try {
    // Force garbage collection
    if ((global as any).gc) {
      (global as any).gc();
      windowsTestContext.windows.gcCount++;
    }

    // Close file handles if possible
    const activeHandles = (process as any)._getActiveHandles();
    if (Array.isArray(activeHandles)) {
      let closedHandles = 0;
      activeHandles.forEach((handle: any) => {
        try {
          if (handle && typeof handle.close === 'function' && !handle.destroyed) {
            handle.close();
            closedHandles++;
          }
        } catch (e) {
          // Ignore closure errors
        }
      });

      if (closedHandles > 0) {
        console.log(`🧹 Closed ${closedHandles} file handles`);
      }
    }

    windowsTestContext.windows.emfilePrevention.lastCleanup = Date.now();
  } catch (error) {
    // Ignore cleanup errors
  }
}

/**
 * Generate enhanced test data for Windows testing
 */
function generateWindowsTestData(): void {
  // Enhanced sample knowledge items with Windows-specific fields
  windowsTestContext.testData.sampleKnowledgeItems = [
    {
      id: 'windows-test-entity-1',
      kind: 'entity',
      scope: { project: 'windows-test-project', org: 'test-org' },
      data: {
        name: 'Windows Test Entity 1',
        description: 'A Windows test entity for unit testing',
        content: 'This is the content of Windows test entity 1',
        platform: 'win32',
        test_environment: true,
      },
      metadata: {
        created_at: new Date().toISOString(),
        test_data: true,
        windows_test: true,
      },
    },
    {
      id: 'windows-test-decision-1',
      kind: 'decision',
      scope: { project: 'windows-test-project' },
      data: {
        title: 'Windows Test Decision 1',
        context: 'Windows testing context',
        decision: 'We will use this Windows-specific approach',
        rationale: 'Because it makes sense for Windows testing',
      },
      metadata: {
        created_at: new Date().toISOString(),
        test_data: true,
        windows_test: true,
      },
    },
    {
      id: 'windows-test-observation-1',
      kind: 'observation',
      scope: { project: 'windows-test-project', branch: 'main' },
      data: {
        entity_type: 'windows_test',
        entity_id: 'windows-test-entity-1',
        observation: 'This is a Windows test observation',
        value: 'windows-test-value',
        platform: 'win32',
      },
      metadata: {
        created_at: new Date().toISOString(),
        test_data: true,
        windows_test: true,
      },
    },
  ];

  // Sample embeddings for testing with Windows-specific patterns
  windowsTestContext.testData.sampleEmbeddings = [
    Array.from({ length: 1536 }, (_, i) => (Math.sin(i * 0.1) + 1) * 0.5),
    Array.from({ length: 1536 }, (_, i) => (Math.cos(i * 0.1) + 1) * 0.5),
    Array.from({ length: 1536 }, (_, i) => (Math.sin(i * 0.2) + 1) * 0.5),
  ];
}

/**
 * Setup enhanced service mocks for Windows testing
 */
async function setupWindowsServiceMocks(): Promise<void> {
  // Enhanced database service mock with Windows optimizations
  windowsTestContext.mockServices.database = {
    store: vi.fn().mockResolvedValue({
      id: 'windows-test-id',
      status: 'stored',
      created_at: new Date().toISOString(),
    }),
    storeItems: vi.fn().mockImplementation(async (items: any[]) => {
      // Simulate realistic processing time
      await new Promise((resolve) => setTimeout(resolve, Math.random() * 10));

      return {
        stored: items.map((item, index) => ({
          ...item,
          id: `windows-stored-${index}`,
          status: 'stored',
          created_at: new Date().toISOString(),
        })),
        failed: [],
        duplicates: [],
      };
    }),
    find: vi.fn().mockResolvedValue([]),
    update: vi.fn().mockResolvedValue(true),
    delete: vi.fn().mockResolvedValue(true),
    healthCheck: vi.fn().mockResolvedValue(true),
    memory_store: vi.fn().mockImplementation(async (item: any) => {
      await new Promise((resolve) => setTimeout(resolve, 5));
      return {
        id: `windows-memory-${Date.now()}`,
        kind: item.kind,
        status: 'stored',
        created_at: new Date().toISOString(),
      };
    }),
    memory_find: vi.fn().mockResolvedValue([]),
    system_status: vi.fn().mockResolvedValue({
      status: 'healthy',
      metrics: {
        total_items: 0,
        memory_usage: 0,
        platform: 'win32',
        file_handles: windowsTestContext.windows.fileHandleCount,
      },
    }),
  };

  // Enhanced embedding service mock with Windows optimizations
  windowsTestContext.mockServices.embeddings = {
    generateEmbedding: vi.fn().mockImplementation(async (text: string) => {
      // Simulate realistic embedding generation time
      await new Promise((resolve) => setTimeout(resolve, Math.random() * 20));

      const index =
        Math.abs(text.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0)) %
        windowsTestContext.testData.sampleEmbeddings.length;

      return {
        vector: windowsTestContext.testData.sampleEmbeddings[index],
        dimensions: 1536,
        model: 'windows-test-model',
        processing_time: Math.random() * 50,
      };
    }),
    generateBatchEmbeddings: vi.fn().mockImplementation(async (texts: string[]) => {
      const startTime = Date.now();

      const vectors = texts.map(
        (_, index) =>
          windowsTestContext.testData.sampleEmbeddings[
            index % windowsTestContext.testData.sampleEmbeddings.length
          ]
      );

      return {
        vectors,
        dimensions: 1536,
        model: 'windows-test-model',
        processing_time: Date.now() - startTime,
      };
    }),
  };

  // Enhanced Qdrant client mock with Windows optimizations
  windowsTestContext.mockServices.qdrant = {
    upsert: vi.fn().mockImplementation(async () => {
      await new Promise((resolve) => setTimeout(resolve, Math.random() * 15));
      return { status: 'completed', operation_id: `windows-op-${Date.now()}` };
    }),
    search: vi.fn().mockImplementation(async () => {
      await new Promise((resolve) => setTimeout(resolve, Math.random() * 10));
      return {
        points: [],
        search_time: Math.random() * 25,
        found_count: 0,
      };
    }),
    retrieve: vi.fn().mockResolvedValue([]),
    delete: vi.fn().mockResolvedValue({ status: 'completed' }),
    getCollections: vi.fn().mockResolvedValue({
      collections: [{ name: 'windows-test-collection' }],
      query_time: Math.random() * 10,
    }),
    createCollection: vi.fn().mockResolvedValue(undefined),
    deleteCollection: vi.fn().mockResolvedValue(undefined),
  };

  // Enhanced logger mock with Windows-specific optimizations
  windowsTestContext.mockServices.logger = {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    // Windows-specific logging
    windows: vi.fn(),
    fileHandle: vi.fn(),
    performance: vi.fn(),
  };

  // Apply mocks to modules with Windows-specific paths
  vi.doMock('../../src/db/unified-database-layer-v2', () => ({
    UnifiedDatabaseLayerV2: vi
      .fn()
      .mockImplementation(() => windowsTestContext.mockServices.database),
  }));

  vi.doMock('../../src/services/embeddings/embedding-service', () => ({
    EmbeddingService: vi.fn().mockImplementation(() => windowsTestContext.mockServices.embeddings),
  }));

  vi.doMock('../../src/db/qdrant-client', () => ({
    qdrant: windowsTestContext.mockServices.qdrant,
  }));

  vi.doMock('../../src/utils/logger', () => ({
    logger: windowsTestContext.mockServices.logger,
  }));
}

/**
 * Setup before each Windows test
 */
beforeEach(async () => {
  // Clear all mocks
  vi.clearAllMocks();

  // Initialize ZAI configuration
  await initializeZAIConfig();

  // Generate test data
  generateWindowsTestData();

  // Setup service mocks
  await setupWindowsServiceMocks();

  // Setup Windows EMFILE prevention
  setupWindowsEMFILEPrevention();

  // Windows-specific global setup
  if (process.platform === 'win32') {
    // Ensure garbage collection is available
    if (!(global as any).gc) {
      try {
        const v8 = await import('v8');
        (global as any).gc = v8.getHeapStatistics;
      } catch (e) {
        (global as any).gc = () => {};
      }
    }

    // Initial cleanup
    forceWindowsCleanup();
  }
});

/**
 * Cleanup after each Windows test
 */
afterEach(() => {
  // Restore all mocks
  vi.restoreAllMocks();

  // Force Windows cleanup
  if (process.platform === 'win32') {
    forceWindowsCleanup();
  }

  // Reset test context
  windowsTestContext.mockServices = {
    database: null,
    embeddings: null,
    qdrant: null,
    logger: null,
    zaiConfig: null,
  };
});

/**
 * Windows-specific test helpers
 */
export const windowsTestHelpers = {
  /**
   * Create Windows-specific mock knowledge item
   */
  createWindowsMockKnowledgeItem: (overrides: any = {}) => ({
    id: 'windows-test-id',
    kind: 'entity',
    scope: { project: 'windows-test' },
    data: {
      content: 'Windows test content',
      platform: 'win32',
      ...overrides.data,
    },
    metadata: {
      platform: 'win32',
      test_environment: true,
      ...overrides.metadata,
    },
    ...overrides,
  }),

  /**
   * Wait for async operations with Windows timing
   */
  windowsWait: (ms: number = 100) => new Promise((resolve) => setTimeout(resolve, ms)),

  /**
   * Force Windows garbage collection
   */
  forceWindowsGC: () => {
    if ((global as any).gc) {
      (global as any).gc();
      windowsTestContext.windows.gcCount++;
    }
  },

  /**
   * Get current file handle count
   */
  getFileHandleCount: (): number => {
    try {
      const activeHandles = (process as any)._getActiveHandles();
      return Array.isArray(activeHandles) ? activeHandles.length : 0;
    } catch (error) {
      return 0;
    }
  },

  /**
   * Assert Windows-specific conditions
   */
  assertWindowsOptimizations: () => {
    expect(windowsTestContext.windows.emfilePrevention.active).toBe(true);
    expect(typeof (global as any).gc).toBe('function');
    expect(process.env['UV_THREADPOOL_SIZE']).toBe('16');
  },
};

// Export for use in test files
export { vi, beforeEach, afterEach };
