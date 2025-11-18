/**
 * Test utility functions and typed mock factories
 * Provides type-safe test helpers for common test scenarios
 */

import { vi } from 'vitest';
import type {
  TestEntity,
  TestConfig,
  MockResponse,
  MockDatabaseResult,
  DeepPartial,
  MockableFunction,
  Constructor
} from '../types/vitest-types';

// =============================================================================
// ENTITY TEST FIXTURES
// =============================================================================

export function createTestEntity(overrides: DeepPartial<TestEntity> = {}): TestEntity {
  return {
    kind: 'entity',
    content: 'Test entity content',
    metadata: {
      test: true,
      created: new Date().toISOString(),
      ...overrides.metadata
    },
    scope: {
      project: 'test-project',
      branch: 'main',
      org: 'test-org',
      ...overrides.scope
    },
    ...overrides
  };
}

export function createTestEntities(count: number, baseOverrides: DeepPartial<TestEntity> = {}): TestEntity[] {
  return Array.from({ length: count }, (_, index) =>
    createTestEntity({
      content: `Test entity ${index}`,
      metadata: {
        ...baseOverrides.metadata,
        index,
        batch: true
      },
      ...baseOverrides
    })
  );
}

// =============================================================================
// MOCK OBJECT FACTORIES
// =============================================================================

export function createMockResponse(overrides: DeepPartial<MockResponse> = {}): MockResponse {
  return {
    status: 200,
    data: {},
    headers: { 'content-type': 'application/json' },
    statusText: 'OK',
    ...overrides
  };
}

export function createMockDatabaseResult<T = any>(
  success: boolean,
  data?: T,
  error?: Error,
  overrides: DeepPartial<MockDatabaseResult<T>> = {}
): MockDatabaseResult<T> {
  const result: MockDatabaseResult<T> = {
    success,
    data,
    error: error ? {
      name: error.name,
      message: error.message,
      stack: error.stack,
      ...error
    } : undefined,
    metadata: { timestamp: new Date().toISOString() },
    ...overrides
  };
  return result;
}

export function createMockConfig(overrides: DeepPartial<TestConfig> = {}): TestConfig {
  return {
    database: {
      host: 'localhost',
      port: 6333,
      collection: 'test-collection',
      ...overrides.database
    },
    logging: {
      level: 'error',
      enabled: false,
      ...overrides.logging
    },
    features: {
      deduplication: true,
      contradiction_detection: true,
      insights: true,
      ...overrides.features
    }
  };
}

// =============================================================================
// DATABASE MOCK FACTORIES
// =============================================================================

export function createMockQdrantClient() {
  return {
    getCollections: vi.fn().mockResolvedValue({
      collections: [{ name: 'test-collection', points_count: 0 }]
    }),
    createCollection: vi.fn().mockResolvedValue(undefined),
    getCollection: vi.fn().mockResolvedValue({
      points_count: 0,
      status: 'green',
      optimizer_status: { ok: true },
      config: {
        params: {
          vector_size: 1536,
          distance: 'Cosine'
        }
      }
    }),
    deleteCollection: vi.fn().mockResolvedValue(undefined),
    upsert: vi.fn().mockResolvedValue({
      operation_id: 'test-operation-id',
      status: 'completed'
    }),
    search: vi.fn().mockResolvedValue([]),
    scroll: vi.fn().mockResolvedValue({
      points: [],
      total_pages: 0,
      next_page_offset: null
    }),
    delete: vi.fn().mockResolvedValue({
      operation_id: 'test-delete-id',
      status: 'completed'
    }),
    update: vi.fn().mockResolvedValue({
      operation_id: 'test-update-id',
      status: 'completed'
    }),
    healthCheck: vi.fn().mockResolvedValue(true),
    close: vi.fn().mockResolvedValue(undefined)
  };
}

export function createMockDatabaseManager() {
  return {
    getClient: vi.fn().mockReturnValue(createMockQdrantClient()),
    healthCheck: vi.fn().mockResolvedValue(true),
    initialize: vi.fn().mockResolvedValue(undefined),
    close: vi.fn().mockResolvedValue(undefined),
    createCollection: vi.fn().mockResolvedValue(undefined),
    deleteCollection: vi.fn().mockResolvedValue(undefined),
    getCollectionInfo: vi.fn().mockResolvedValue({
      name: 'test-collection',
      points_count: 0,
      status: 'green'
    })
  };
}

// =============================================================================
// SERVICE MOCK FACTORIES
// =============================================================================

export function createMockMemoryStoreService() {
  return {
    store: vi.fn().mockResolvedValue(createMockDatabaseResult(true, { id: 'test-id' })),
    find: vi.fn().mockResolvedValue(createMockDatabaseResult(true, [])),
    update: vi.fn().mockResolvedValue(createMockDatabaseResult(true, { id: 'test-id' })),
    delete: vi.fn().mockResolvedValue(createMockDatabaseResult(true)),
    batch: vi.fn().mockResolvedValue(createMockDatabaseResult(true, { ids: ['id1', 'id2'] })),
    healthCheck: vi.fn().mockResolvedValue(true)
  };
}

export function createMockEmbeddingService() {
  return {
    generateEmbedding: vi.fn().mockResolvedValue(new Array(1536).fill(0.1)),
    batchGenerateEmbeddings: vi.fn().mockResolvedValue([
      new Array(1536).fill(0.1),
      new Array(1536).fill(0.2)
    ]),
    healthCheck: vi.fn().mockResolvedValue(true)
  };
}

export function createMockDeduplicationService() {
  return {
    checkDuplicate: vi.fn().mockResolvedValue({ isDuplicate: false, confidence: 0 }),
    processDuplicates: vi.fn().mockResolvedValue({
      processed: 0,
      duplicates: [],
      kept: []
    }),
    healthCheck: vi.fn().mockResolvedValue(true)
  };
}

export function createMockInsightService() {
  return {
    generateInsights: vi.fn().mockResolvedValue({
      insights: [],
      confidence: 0.8,
      patterns: []
    }),
    analyzePatterns: vi.fn().mockResolvedValue({
      patterns: [],
      recommendations: []
    }),
    healthCheck: vi.fn().mockResolvedValue(true)
  };
}

// =============================================================================
// HTTP CLIENT MOCK FACTORIES
// =============================================================================

export function createMockHttpClient() {
  return {
    get: vi.fn().mockResolvedValue(createMockResponse()),
    post: vi.fn().mockResolvedValue(createMockResponse()),
    put: vi.fn().mockResolvedValue(createMockResponse()),
    patch: vi.fn().mockResolvedValue(createMockResponse()),
    delete: vi.fn().mockResolvedValue(createMockResponse()),
    request: vi.fn().mockResolvedValue(createMockResponse()),
    setHeader: vi.fn(),
    removeHeader: vi.fn(),
    clearHeaders: vi.fn()
  };
}

// =============================================================================
// LOGGER MOCK FACTORIES
// =============================================================================

export function createMockLogger() {
  return {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    child: vi.fn().mockReturnValue(createMockLogger()),
    level: 'error'
  };
}

// =============================================================================
// CONFIGURATION MOCK FACTORIES
// =============================================================================

export function createMockConfigurationService() {
  return {
    get: vi.fn(),
    set: vi.fn(),
    getAll: vi.fn().mockReturnValue({}),
    validate: vi.fn().mockResolvedValue(true),
    reload: vi.fn().mockResolvedValue(undefined),
    watch: vi.fn(),
    unwatch: vi.fn()
  };
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

export function createMockEventEmitter() {
  return {
    on: vi.fn(),
    off: vi.fn(),
    emit: vi.fn(),
    once: vi.fn(),
    removeAllListeners: vi.fn(),
    listenerCount: vi.fn().mockReturnValue(0),
    listeners: vi.fn().mockReturnValue([])
  };
}

export function createAsyncTimeout<T = any>(data: T, delay: number = 100): Promise<T> {
  return new Promise(resolve => setTimeout(() => resolve(data), delay));
}

export function createAsyncError(error: Error, delay: number = 100): Promise<never> {
  return new Promise((_, reject) => setTimeout(() => reject(error), delay));
}

// =============================================================================
// TYPE GUARDS AND ASSERTIONS
// =============================================================================

export function assertIsError(error: unknown): asserts error is Error {
  if (!(error instanceof Error)) {
    throw new Error(`Expected Error, got ${typeof error}`);
  }
}

export function assertIsTestEntity(obj: unknown): asserts obj is TestEntity {
  if (!obj || typeof obj !== 'object') {
    throw new Error('Expected TestEntity object');
  }

  const entity = obj as any;
  if (typeof entity.kind !== 'string' || typeof entity.content !== 'string') {
    throw new Error('Invalid TestEntity structure');
  }
}

export function assertHasProperty<T extends Record<string, any>, K extends keyof T>(
  obj: T,
  property: K
): asserts obj is T & Required<Pick<T, K>> {
  if (!(property in obj) || obj[property] === undefined) {
    throw new Error(`Expected property ${String(property)} to exist`);
  }
}

// =============================================================================
// TEST DATA BUILDERS
// =============================================================================

export class TestDataBuilder {
  private data: any = {};

  constructor(private initialData: any = {}) {
    this.data = { ...initialData };
  }

  with<K extends keyof any>(key: K, value: any[K]): this {
    this.data[key] = value;
    return this;
  }

  withMany<K extends keyof any>(updates: Partial<any>): this {
    this.data = { ...this.data, ...updates };
    return this;
  }

  build(): any {
    return { ...this.data };
  }

  reset(): this {
    this.data = { ...this.initialData };
    return this;
  }
}

export class EntityBuilder extends TestDataBuilder {
  constructor() {
    super(createTestEntity());
  }

  withKind(kind: string): this {
    return this.with('kind', kind);
  }

  withContent(content: string): this {
    return this.with('content', content);
  }

  withMetadata(metadata: Record<string, any>): this {
    return this.with('metadata', { ...this.data.metadata, ...metadata });
  }

  withProject(project: string): this {
    return this.with('scope', { ...this.data.scope, project });
  }

  withBranch(branch: string): this {
    return this.with('scope', { ...this.data.scope, branch });
  }

  build(): TestEntity {
    return super.build() as TestEntity;
  }
}

// =============================================================================
// EXPORTED FACTORY COLLECTION
// =============================================================================

export const MockFactories = {
  entity: createTestEntity,
  entities: createTestEntities,
  response: createMockResponse,
  databaseResult: createMockDatabaseResult,
  config: createMockConfig,
  qdrantClient: createMockQdrantClient,
  databaseManager: createMockDatabaseManager,
  memoryStore: createMockMemoryStoreService,
  embedding: createMockEmbeddingService,
  deduplication: createMockDeduplicationService,
  insight: createMockInsightService,
  httpClient: createMockHttpClient,
  logger: createMockLogger,
  configuration: createMockConfigurationService,
  eventEmitter: createMockEventEmitter,
  asyncTimeout: createAsyncTimeout,
  asyncError: createAsyncError
};

export const Builders = {
  entity: () => new EntityBuilder(),
  data: (initial: any = {}) => new TestDataBuilder(initial)
};