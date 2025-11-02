/**
 * Database Mocks for CI Testing
 *
 * Provides consistent database mocks that simulate Qdrant behavior
 * without requiring external dependencies in CI environments.
 */

import { vi } from 'vitest';

// Mock Qdrant client
export const mockQdrantClient = {
  // Collection management
  getCollections: vi.fn().mockResolvedValue({
    collections: [
      {
        name: 'test-collection',
        points_count: 0,
        vectors_count: 0,
        indexed_vectors_count: 0,
        config: {
          params: {
            vector_size: 1536,
            distance: 'Cosine',
          },
        },
      },
    ],
  }),
  createCollection: vi.fn().mockResolvedValue(undefined),
  deleteCollection: vi.fn().mockResolvedValue(undefined),
  getCollection: vi.fn().mockResolvedValue({
    name: 'test-collection',
    points_count: 0,
    vectors_count: 0,
    indexed_vectors_count: 0,
    config: {
      params: {
        vector_size: 1536,
        distance: 'Cosine',
      },
    },
  }),

  // Point operations
  upsert: vi.fn().mockImplementation(async (collectionName: string, points: any[]) => {
    // Simulate successful upsert
    return {
      operation_id: `mock-upsert-${Date.now()}`,
      status: 'completed',
      upserted_count: points.length,
    };
  }),
  search: vi.fn().mockImplementation(async (collectionName: string, searchRequest: any) => {
    // Simulate search results
    const mockResults = Array.from(
      { length: Math.min(searchRequest.limit || 10, 3) },
      (_, index) => ({
        id: `mock-point-${index}`,
        score: 0.9 - index * 0.1,
        payload: {
          content: `Mock content ${index}`,
          kind: 'entity',
          scope: { project: 'test' },
          created_at: new Date().toISOString(),
        },
        vector: Array.from({ length: 1536 }, () => Math.random()),
      })
    );

    return {
      result: mockResults,
      status: 'completed',
      time: 0.015,
    };
  }),
  retrieve: vi.fn().mockImplementation(async (collectionName: string, ids: string[]) => {
    // Simulate retrieve results
    return ids.map((id) => ({
      id,
      payload: {
        content: `Retrieved content for ${id}`,
        kind: 'entity',
        scope: { project: 'test' },
        created_at: new Date().toISOString(),
      },
      vector: Array.from({ length: 1536 }, () => Math.random()),
    }));
  }),
  delete: vi.fn().mockImplementation(async (collectionName: string, ids: string[]) => {
    return {
      status: 'completed',
      deleted_count: ids.length,
    };
  }),
  scroll: vi.fn().mockResolvedValue({
    result: {
      points: [],
      next_page_offset: null,
    },
    status: 'completed',
  }),
  count: vi.fn().mockResolvedValue({
    count: 0,
  }),
  update: vi.fn().mockResolvedValue({
    operation_id: `mock-update-${Date.now()}`,
    status: 'completed',
    updated_count: 1,
  }),

  // Health check
  healthCheck: vi.fn().mockResolvedValue(true),

  // Advanced operations
  recommend: vi.fn().mockResolvedValue({
    result: [],
    status: 'completed',
  }),
  searchBatch: vi.fn().mockResolvedValue({
    results: [],
    status: 'completed',
  }),
};

// Mock unified database layer
export const mockUnifiedDatabaseLayer = {
  // Basic CRUD operations
  store: vi.fn().mockImplementation(async (items: any[]) => {
    return items.map((item) => ({
      id: item.id || `generated-id-${Date.now()}`,
      status: 'stored',
      kind: item.kind,
      created_at: new Date().toISOString(),
    }));
  }),
  find: vi.fn().mockResolvedValue([]),
  update: vi.fn().mockResolvedValue(true),
  delete: vi.fn().mockResolvedValue(true),

  // Advanced operations
  search: vi.fn().mockResolvedValue({
    results: [],
    total_count: 0,
    confidence_score: 0.8,
    search_strategy: 'hybrid',
  }),
  batchSearch: vi.fn().mockResolvedValue([]),
  semanticSearch: vi.fn().mockResolvedValue([]),
  hybridSearch: vi.fn().mockResolvedValue([]),

  // Collection management
  createCollection: vi.fn().mockResolvedValue(true),
  dropCollection: vi.fn().mockResolvedValue(true),
  listCollections: vi.fn().mockResolvedValue([]),
  getCollectionStats: vi.fn().mockResolvedValue({
    name: 'test-collection',
    points_count: 0,
    size_bytes: 0,
  }),

  // Health and status
  healthCheck: vi.fn().mockResolvedValue({
    status: 'healthy',
    database_connected: true,
    collections_count: 0,
  }),
  getConnectionInfo: vi.fn().mockResolvedValue({
    url: 'mock://localhost:6333',
    connected: true,
    version: 'mock-version',
  }),

  // Transaction support
  beginTransaction: vi.fn().mockResolvedValue({
    id: `mock-tx-${Date.now()}`,
    active: true,
  }),
  commitTransaction: vi.fn().mockResolvedValue(true),
  rollbackTransaction: vi.fn().mockResolvedValue(true),

  // Index management
  createIndex: vi.fn().mockResolvedValue(true),
  dropIndex: vi.fn().mockResolvedValue(true),
  listIndexes: vi.fn().mockResolvedValue([]),

  // Analytics
  getMetrics: vi.fn().mockResolvedValue({
    total_points: 0,
    total_collections: 0,
    storage_used_bytes: 0,
    query_count: 0,
    average_query_time_ms: 0,
  }),
};

// Mock database factory
export const mockDatabaseFactory = {
  create: vi.fn().mockImplementation((config: any) => {
    return mockUnifiedDatabaseLayer;
  }),
  createWithDefaults: vi.fn().mockReturnValue(mockUnifiedDatabaseLayer),
  createInMemory: vi.fn().mockReturnValue(mockUnifiedDatabaseLayer),
  createTestInstance: vi.fn().mockReturnValue(mockUnifiedDatabaseLayer),
};

// Mock database adapter
export const mockQdrantAdapter = {
  // Adapter-specific operations
  connect: vi.fn().mockResolvedValue(true),
  disconnect: vi.fn().mockResolvedValue(true),
  isConnected: vi.fn().mockReturnValue(true),

  // Collection operations
  createCollection: vi.fn().mockResolvedValue(true),
  deleteCollection: vi.fn().mockResolvedValue(true),
  getCollectionInfo: vi.fn().mockResolvedValue({
    name: 'test',
    vectors: 1536,
    points: 0,
  }),

  // Point operations
  upsertPoints: vi.fn().mockResolvedValue({ status: 'completed' }),
  searchPoints: vi.fn().mockResolvedValue({ points: [] }),
  getPoints: vi.fn().mockResolvedValue({ points: [] }),
  deletePoints: vi.fn().mockResolvedValue({ status: 'completed' }),

  // Batch operations
  batchUpsert: vi.fn().mockResolvedValue({ status: 'completed' }),
  batchDelete: vi.fn().mockResolvedValue({ status: 'completed' }),

  // Schema validation
  validateSchema: vi.fn().mockResolvedValue({ valid: true }),
  inferSchema: vi.fn().mockResolvedValue({ schema: {} }),

  // Performance monitoring
  getPerformanceMetrics: vi.fn().mockResolvedValue({
    avg_response_time_ms: 15,
    p95_response_time_ms: 30,
    p99_response_time_ms: 50,
    requests_per_second: 100,
  }),
};

// Helper functions for database testing
export const databaseTestHelpers = {
  /**
   * Create a mock knowledge item for testing
   */
  createMockKnowledgeItem: (overrides: any = {}) => ({
    id: `test-item-${Date.now()}`,
    kind: 'entity',
    scope: { project: 'test', org: 'test' },
    data: {
      content: 'Test content',
      name: 'Test Item',
    },
    metadata: {
      created_at: new Date().toISOString(),
      test_data: true,
    },
    ...overrides,
  }),

  /**
   * Create mock search results
   */
  createMockSearchResults: (count: number = 5) => {
    return Array.from({ length: count }, (_, index) => ({
      id: `mock-result-${index}`,
      kind: 'entity',
      scope: { project: 'test' },
      data: { content: `Mock result ${index}` },
      confidence_score: 0.9 - index * 0.1,
      match_type: 'semantic',
    }));
  },

  /**
   * Assert database operation was called correctly
   */
  assertDatabaseOperation: (mockFn: any, expectedArgs: any[]) => {
    expect(mockFn).toHaveBeenCalledWith(...expectedArgs);
  },

  /**
   * Reset all database mocks
   */
  resetDatabaseMocks: () => {
    Object.values(mockQdrantClient).forEach((method) => {
      if (vi.isMockFunction(method)) {
        vi.clearAllMocks();
      }
    });
    Object.values(mockUnifiedDatabaseLayer).forEach((method) => {
      if (vi.isMockFunction(method)) {
        vi.clearAllMocks();
      }
    });
  },
};

// Export for use in tests
export {
  mockQdrantClient as qdrant,
  mockUnifiedDatabaseLayer as database,
  mockDatabaseFactory as databaseFactory,
  mockQdrantAdapter as qdrantAdapter,
};
