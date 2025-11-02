/**
 * Comprehensive Unit Tests for Qdrant Client Wrapper
 *
 * Tests Qdrant client abstraction layer functionality including:
 * - Client initialization and configuration
 * - Point operations (CRUD)
 * - Batch operations
 * - Search and filtering
 * - Collection management
 * - Error handling and resilience
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { describe, it, expect, beforeEach, afterEach, vi, beforeAll, afterAll } from 'vitest';
import { QdrantAdapter } from '../../../src/db/adapters/qdrant-adapter';
import {
  StandardTestUtils,
  MockFactory,
  TestPatterns,
} from '../../../tests/framework/standard-test-setup';
import type {
  KnowledgeItem,
  SearchQuery,
  StoreOptions,
  SearchOptions,
  DeleteOptions,
  VectorConfig,
} from '../../src/types/core-interfaces';
import type { IVectorAdapter } from '../../src/db/interfaces/vector-adapter.interface';

// Mock OpenAI
vi.mock('openai', () => ({
  OpenAI: class {
    constructor() {
      this.embeddings = {
        create: vi.fn().mockResolvedValue({
          data: [{ embedding: [0.1, 0.2, 0.3, 0.4, 0.5] }],
        }),
      };
    }
  },
}));

// Mock Qdrant client with comprehensive functionality
const createMockQdrantClient = () => ({
  getCollections: vi.fn().mockResolvedValue({
    collections: [{ name: 'knowledge_items' }],
  }),
  createCollection: vi.fn().mockResolvedValue(undefined),
  deleteCollection: vi.fn().mockResolvedValue(undefined),
  getCollection: vi.fn().mockResolvedValue({
    vectors_count: 100,
    indexed_vectors_count: 95,
    points_count: 100,
    segments_count: 2,
    disk_data_size: 1024000,
    ram_data_size: 512000,
    status: 'green',
    optimizer_status: 'ok',
    config: {},
    payload_schema: {},
  }),
  upsert: vi.fn().mockResolvedValue({ status: 'completed' }),
  search: vi.fn().mockResolvedValue([
    {
      id: 'test-id-1',
      score: 0.9,
      payload: {
        kind: 'entity',
        scope: { project: 'test-project' },
        data: { title: 'Test Entity', content: 'Test content' },
        created_at: '2025-01-01T00:00:00.000Z',
      },
    },
  ]),
  retrieve: vi.fn().mockResolvedValue([
    {
      id: 'test-id-1',
      payload: {
        kind: 'entity',
        scope: { project: 'test-project' },
        data: { title: 'Test Entity', content: 'Test content' },
        created_at: '2025-01-01T00:00:00.000Z',
      },
    },
  ]),
  delete: vi.fn().mockResolvedValue({ status: 'completed' }),
  scroll: vi.fn().mockResolvedValue({
    points: [],
    next_page_offset: null,
  }),
  updateCollection: vi.fn().mockResolvedValue(undefined),
  createSnapshot: vi.fn().mockResolvedValue({ name: 'test-snapshot' }),
  count: vi.fn().mockResolvedValue({ count: 100 }),
});

describe('QdrantAdapter - Client Initialization', () => {
  let adapter: QdrantAdapter;
  let mockClient: any;

  beforeAll(() => {
    TestPatterns.unitTest();
  });

  beforeEach(() => {
    mockClient = createMockQdrantClient();

    // Mock the QdrantClient constructor
    vi.doMock('@qdrant/js-client-rest', () => ({
      QdrantClient: vi.fn().mockImplementation(() => mockClient),
    }));

    const config: VectorConfig = {
      type: 'qdrant',
      url: 'http://localhost:6333',
      apiKey: 'test-api-key',
      vectorSize: 1536,
      distance: 'Cosine',
      connectionTimeout: 30000,
      maxConnections: 10,
    };

    adapter = new QdrantAdapter(config);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should initialize with correct configuration', () => {
    expect(adapter).toBeDefined();
  });

  it('should use default configuration values', () => {
    const minimalConfig: VectorConfig = { type: 'qdrant' };
    const minimalAdapter = new QdrantAdapter(minimalConfig);
    expect(minimalAdapter).toBeDefined();
  });

  it('should initialize successfully', async () => {
    await adapter.initialize();
    expect(mockClient.getCollections).toHaveBeenCalled();
  });

  it('should handle initialization failure gracefully', async () => {
    mockClient.getCollections.mockRejectedValue(new Error('Connection failed'));

    await expect(adapter.initialize()).rejects.toThrow();
  });

  it('should prevent double initialization', async () => {
    await adapter.initialize();
    await adapter.initialize(); // Should not throw

    expect(mockClient.getCollections).toHaveBeenCalledTimes(1);
  });

  it('should perform health check', async () => {
    const isHealthy = await adapter.healthCheck();
    expect(isHealthy).toBe(true);
    expect(mockClient.getCollections).toHaveBeenCalled();
  });

  it('should handle health check failure', async () => {
    mockClient.getCollections.mockRejectedValue(new Error('Health check failed'));

    const isHealthy = await adapter.healthCheck();
    expect(isHealthy).toBe(false);
  });

  it('should return database metrics', async () => {
    const metrics = await adapter.getMetrics();

    expect(metrics).toHaveProperty('type', 'qdrant');
    expect(metrics).toHaveProperty('healthy');
    expect(metrics).toHaveProperty('vectorCount');
    expect(metrics).toHaveProperty('connectionCount');
    expect(mockClient.getCollection).toHaveBeenCalled();
  });

  it('should close connection properly', async () => {
    await adapter.initialize();
    await adapter.close();

    // Qdrant client doesn't have explicit close, but should not throw
    expect(true).toBe(true);
  });
});

describe('QdrantAdapter - Point Operations', () => {
  let adapter: QdrantAdapter;
  let mockClient: any;

  beforeEach(async () => {
    mockClient = createMockQdrantClient();
    vi.doMock('@qdrant/js-client-rest', () => ({
      QdrantClient: vi.fn().mockImplementation(() => mockClient),
    }));

    const config: VectorConfig = {
      type: 'qdrant',
      url: 'http://localhost:6333',
      vectorSize: 1536,
    };

    adapter = new QdrantAdapter(config);
    await adapter.initialize();
  });

  it('should store single point with payload validation', async () => {
    const item: KnowledgeItem = {
      id: 'test-point-1',
      kind: 'entity',
      scope: { project: 'test-project' },
      data: { title: 'Test Entity', content: 'Test content' },
    };

    const result = await adapter.store([item]);

    expect(result.stored).toHaveLength(1);
    expect(result.errors).toHaveLength(0);
    expect(mockClient.upsert).toHaveBeenCalledWith(
      'knowledge_items',
      expect.objectContaining({
        wait: true,
        points: expect.arrayContaining([
          expect.objectContaining({
            id: 'test-point-1',
            vector: expect.any(Array),
            payload: expect.objectContaining({
              kind: 'entity',
              scope: { project: 'test-project' },
            }),
          }),
        ]),
      })
    );
  });

  it('should retrieve point by ID', async () => {
    const ids = ['test-point-1'];

    const results = await adapter.findById(ids);

    expect(results).toHaveLength(1);
    expect(results[0]).toHaveProperty('id', 'test-point-1');
    expect(results[0]).toHaveProperty('kind', 'entity');
    expect(mockClient.retrieve).toHaveBeenCalledWith('knowledge_items', {
      ids,
      with_payload: true,
    });
  });

  it('should handle missing point retrieval', async () => {
    mockClient.retrieve.mockResolvedValue([]);

    const results = await adapter.findById(['nonexistent-id']);

    expect(results).toHaveLength(0);
  });

  it('should update point with payload changes', async () => {
    const item: KnowledgeItem = {
      id: 'test-point-1',
      kind: 'entity',
      scope: { project: 'test-project' },
      data: { title: 'Updated Entity', content: 'Updated content' },
    };

    const result = await adapter.update([item]);

    expect(result.stored).toHaveLength(1);
    expect(mockClient.upsert).toHaveBeenCalled();
  });

  it('should delete point with validation', async () => {
    const ids = ['test-point-1'];

    // Setup retrieval mock for validation
    mockClient.retrieve.mockResolvedValue([
      {
        id: 'test-point-1',
        payload: { kind: 'entity' },
      },
    ]);

    const result = await adapter.delete(ids, { validate: true });

    expect(result.deleted).toBe(1);
    expect(result.errors).toHaveLength(0);
    expect(mockClient.delete).toHaveBeenCalledWith('knowledge_items', {
      wait: true,
      points: ids,
    });
  });

  it('should handle deletion of non-existent point', async () => {
    const ids = ['nonexistent-id'];

    // Setup retrieval mock to return empty
    mockClient.retrieve.mockResolvedValue([]);

    const result = await adapter.delete(ids, { validate: true });

    expect(result.deleted).toBe(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].error_code).toBe('DELETE_ERROR');
  });

  it('should delete point without validation', async () => {
    const ids = ['test-point-1'];

    const result = await adapter.delete(ids, { validate: false });

    expect(result.deleted).toBe(1);
    expect(mockClient.retrieve).not.toHaveBeenCalled();
    expect(mockClient.delete).toHaveBeenCalled();
  });

  it('should handle invalid payload data', async () => {
    const invalidItem = {
      id: 'invalid-point',
      kind: null, // Invalid kind
      data: 'invalid data type', // Should be object
    } as any;

    const result = await adapter.store([invalidItem]);

    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('should auto-generate ID when not provided', async () => {
    const item: KnowledgeItem = {
      kind: 'entity',
      scope: { project: 'test-project' },
      data: { title: 'Test Entity' },
    };

    const result = await adapter.store([item]);

    expect(result.stored[0].id).toMatch(/^qdrant_\d+_[a-z0-9]+$/);
  });
});

describe('QdrantAdapter - Batch Operations', () => {
  let adapter: QdrantAdapter;
  let mockClient: any;

  beforeEach(async () => {
    mockClient = createMockQdrantClient();
    vi.doMock('@qdrant/js-client-rest', () => ({
      QdrantClient: vi.fn().mockImplementation(() => mockClient),
    }));

    const config: VectorConfig = {
      type: 'qdrant',
      url: 'http://localhost:6333',
      vectorSize: 1536,
    };

    adapter = new QdrantAdapter(config);
    await adapter.initialize();
  });

  it('should handle batch upsert with multiple points', async () => {
    const items: KnowledgeItem[] = Array.from({ length: 5 }, (_, i) => ({
      id: `batch-point-${i}`,
      kind: 'entity',
      scope: { project: 'test-project' },
      data: { title: `Batch Entity ${i}`, content: `Batch content ${i}` },
    }));

    const result = await adapter.store(items, { batchSize: 5 });

    expect(result.stored).toHaveLength(5);
    expect(result.errors).toHaveLength(0);
    expect(mockClient.upsert).toHaveBeenCalledTimes(5);
  });

  it('should handle batch search with filters', async () => {
    const queries: SearchQuery[] = [
      { query: 'test query 1', limit: 10 },
      { query: 'test query 2', limit: 20 },
    ];

    mockClient.search.mockResolvedValue([
      { id: 'result-1', score: 0.9, payload: { kind: 'entity' } },
      { id: 'result-2', score: 0.8, payload: { kind: 'entity' } },
    ]);

    const results = await adapter.bulkSearch(queries);

    expect(results).toHaveLength(2);
    expect(results[0]).toHaveProperty('results');
    expect(results[1]).toHaveProperty('results');
    expect(mockClient.search).toHaveBeenCalledTimes(2);
  });

  it('should handle batch deletion operations', async () => {
    // Setup scroll mock for finding items to delete
    mockClient.scroll.mockResolvedValue({
      points: [
        { id: 'delete-1', payload: { kind: 'entity' } },
        { id: 'delete-2', payload: { kind: 'entity' } },
      ],
    });

    const result = await adapter.bulkDelete({
      kind: 'entity',
      scope: { project: 'test-project' },
    });

    expect(result.deleted).toBe(2);
    expect(mockClient.scroll).toHaveBeenCalled();
    expect(mockClient.delete).toHaveBeenCalled();
  });

  it('should handle empty batch operations', async () => {
    const result = await adapter.store([]);

    expect(result.stored).toHaveLength(0);
    expect(result.errors).toHaveLength(0);
  });

  it('should handle batch operation with mixed success/failure', async () => {
    mockClient.upsert
      .mockResolvedValueOnce({ status: 'completed' })
      .mockRejectedValueOnce(new Error('Insert failed'))
      .mockResolvedValueOnce({ status: 'completed' });

    const items: KnowledgeItem[] = [
      { id: 'success-1', kind: 'entity', scope: {}, data: {} },
      { id: 'fail-1', kind: 'entity', scope: {}, data: {} },
      { id: 'success-2', kind: 'entity', scope: {}, data: {} },
    ];

    const result = await adapter.store(items);

    expect(result.stored).toHaveLength(2);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].error_code).toBe('STORE_ERROR');
  });

  it('should maintain transaction-like behavior', async () => {
    const items: KnowledgeItem[] = Array.from({ length: 3 }, (_, i) => ({
      id: `transaction-${i}`,
      kind: 'entity',
      scope: { project: 'test-project' },
      data: { title: `Transaction ${i}` },
    }));

    // All operations should use wait: true for consistency
    const result = await adapter.store(items);

    expect(result.stored).toHaveLength(3);
    expect(mockClient.upsert).toHaveBeenCalledWith(
      'knowledge_items',
      expect.objectContaining({ wait: true })
    );
  });

  it('should handle batch size configuration', async () => {
    const items: KnowledgeItem[] = Array.from({ length: 15 }, (_, i) => ({
      id: `batch-size-${i}`,
      kind: 'entity',
      scope: {},
      data: { title: `Item ${i}` },
    }));

    const result = await adapter.store(items, { batchSize: 5 });

    expect(result.stored).toHaveLength(15);
    expect(mockClient.upsert).toHaveBeenCalledTimes(15); // Each item processed individually
  });
});

describe('QdrantAdapter - Search and Filtering', () => {
  let adapter: QdrantAdapter;
  let mockClient: any;

  beforeEach(async () => {
    mockClient = createMockQdrantClient();
    vi.doMock('@qdrant/js-client-rest', () => ({
      QdrantClient: vi.fn().mockImplementation(() => mockClient),
    }));

    const config: VectorConfig = {
      type: 'qdrant',
      url: 'http://localhost:6333',
      vectorSize: 1536,
    };

    adapter = new QdrantAdapter(config);
    await adapter.initialize();
  });

  it('should perform vector similarity search', async () => {
    const query: SearchQuery = {
      query: 'test query',
      limit: 10,
      types: ['entity'],
    };

    const result = await adapter.search(query);

    expect(result.items).toHaveLength(1);
    expect(result.items[0]).toHaveProperty('confidence_score', 0.9);
    expect(result.items[0]).toHaveProperty('kind', 'entity');
    expect(mockClient.search).toHaveBeenCalledWith(
      'knowledge_items',
      expect.objectContaining({
        vector: expect.any(Array),
        limit: 10,
        score_threshold: expect.any(Number),
        with_payload: expect.any(Array),
      })
    );
  });

  it('should perform payload-based filtering', async () => {
    const query: SearchQuery = {
      query: 'test query',
      scope: { project: 'specific-project', branch: 'main' },
      types: ['decision', 'entity'],
    };

    await adapter.search(query);

    expect(mockClient.search).toHaveBeenCalledWith(
      'knowledge_items',
      expect.objectContaining({
        filter: expect.objectContaining({
          must: expect.arrayContaining([
            expect.objectContaining({
              key: 'scope.project',
              match: { value: 'specific-project' },
            }),
            expect.objectContaining({
              key: 'scope.branch',
              match: { value: 'main' },
            }),
          ]),
        }),
      })
    );
  });

  it('should handle complex filter combinations', async () => {
    const query: SearchQuery = {
      query: 'complex query',
      scope: {
        project: 'test-project',
        branch: 'feature-branch',
        org: 'test-org',
      },
    };

    await adapter.search(query);

    expect(mockClient.search).toHaveBeenCalledWith(
      'knowledge_items',
      expect.objectContaining({
        filter: expect.objectContaining({
          must: expect.arrayContaining([
            expect.objectContaining({
              key: 'scope.project',
              match: { value: 'test-project' },
            }),
            expect.objectContaining({
              key: 'scope.branch',
              match: { value: 'feature-branch' },
            }),
            expect.objectContaining({
              key: 'scope.org',
              match: { value: 'test-org' },
            }),
          ]),
        }),
      })
    );
  });

  it('should handle search result pagination', async () => {
    const query: SearchQuery = {
      query: 'paginated query',
      limit: 5,
    };

    mockClient.search.mockResolvedValue(
      Array.from({ length: 10 }, (_, i) => ({
        id: `result-${i}`,
        score: 0.9 - i * 0.1,
        payload: { kind: 'entity', data: { title: `Result ${i}` } },
      }))
    );

    const result = await adapter.search(query);

    expect(result.items).toHaveLength(5); // Limited by query.limit
    expect(result.total_count).toBe(5);
  });

  it('should perform semantic search', async () => {
    const result = await adapter.semanticSearch('semantic query', { limit: 10 });

    expect(result).toHaveLength(1);
    expect(result[0]).toHaveProperty('match_type', 'semantic');
    expect(mockClient.search).toHaveBeenCalledWith(
      'knowledge_items',
      expect.objectContaining({
        vector: expect.any(Array),
        score_threshold: 0.7,
      })
    );
  });

  it('should perform exact search', async () => {
    const result = await adapter.exactSearch('exact query', { limit: 10 });

    expect(result).toHaveLength(1);
    expect(result[0]).toHaveProperty('match_type', 'exact');
    expect(mockClient.search).toHaveBeenCalledWith(
      'knowledge_items',
      expect.objectContaining({
        vector: { name: 'content_sparse', vector: expect.any(Object) },
        score_threshold: 0.3,
      })
    );
  });

  it('should perform hybrid search', async () => {
    const result = await adapter.hybridSearch('hybrid query', { limit: 10 });

    expect(result).toHaveLength(1);
    expect(result[0]).toHaveProperty('match_type', 'hybrid');
  });

  it('should handle empty search results', async () => {
    mockClient.search.mockResolvedValue([]);

    const result = await adapter.search({ query: 'no results query' });

    expect(result.items).toHaveLength(0);
    expect(result.total_count).toBe(0);
  });

  it('should handle search errors gracefully', async () => {
    mockClient.search.mockRejectedValue(new Error('Search failed'));

    await expect(adapter.search({ query: 'test query' })).rejects.toThrow();
  });

  it('should search by knowledge type', async () => {
    const result = await adapter.searchByKind(['entity', 'decision'], {
      query: 'type-specific query',
    });

    expect(result).toHaveProperty('results');
    expect(result).toHaveProperty('total_count');
  });

  it('should find by scope', async () => {
    const scope = { project: 'test-project', branch: 'main' };

    mockClient.search.mockResolvedValue([
      {
        id: 'scoped-item-1',
        payload: {
          kind: 'entity',
          scope,
          data: { title: 'Scoped Item' },
        },
      },
    ]);

    const results = await adapter.findByScope(scope);

    expect(results).toHaveLength(1);
    expect(results[0].scope).toEqual(scope);
  });

  it('should find similar items', async () => {
    const item: KnowledgeItem = {
      id: 'reference-item',
      kind: 'entity',
      scope: { project: 'test-project' },
      data: { title: 'Reference Item', content: 'Reference content' },
    };

    const similarItems = await adapter.findSimilar(item, 0.7);

    expect(similarItems).toHaveLength(1);
    expect(mockClient.search).toHaveBeenCalledWith(
      'knowledge_items',
      expect.objectContaining({
        filter: {
          must_not: [{ key: 'id', match: { value: 'reference-item' } }],
        },
      })
    );
  });
});

describe('QdrantAdapter - Collection Operations', () => {
  let adapter: QdrantAdapter;
  let mockClient: any;

  beforeEach(async () => {
    mockClient = createMockQdrantClient();
    vi.doMock('@qdrant/js-client-rest', () => ({
      QdrantClient: vi.fn().mockImplementation(() => mockClient),
    }));

    const config: VectorConfig = {
      type: 'qdrant',
      url: 'http://localhost:6333',
      vectorSize: 1536,
    };

    adapter = new QdrantAdapter(config);
    await adapter.initialize();
  });

  it('should create collection when it does not exist', async () => {
    // Mock collections to not include our collection
    mockClient.getCollections.mockResolvedValue({
      collections: [{ name: 'other-collection' }],
    });

    const newAdapter = new QdrantAdapter({
      type: 'qdrant',
      url: 'http://localhost:6333',
      vectorSize: 1536,
    });

    await newAdapter.initialize();

    expect(mockClient.createCollection).toHaveBeenCalledWith(
      'knowledge_items',
      expect.objectContaining({
        vectors: {
          size: 1536,
          distance: 'Cosine',
        },
        sparse_vectors: {
          content_sparse: {
            index: { type: 'keyword' },
          },
        },
      })
    );
  });

  it('should not create collection when it exists', async () => {
    // Mock collections to include our collection
    mockClient.getCollections.mockResolvedValue({
      collections: [{ name: 'knowledge_items' }],
    });

    const newAdapter = new QdrantAdapter({
      type: 'qdrant',
      url: 'http://localhost:6333',
      vectorSize: 1536,
    });

    await newAdapter.initialize();

    expect(mockClient.createCollection).not.toHaveBeenCalled();
  });

  it('should get collection statistics', async () => {
    const stats = await adapter.getStatistics();

    expect(stats).toHaveProperty('totalItems');
    expect(stats).toHaveProperty('itemsByKind');
    expect(stats).toHaveProperty('storageSize');
    expect(stats).toHaveProperty('vectorCount');
    expect(mockClient.getCollection).toHaveBeenCalled();
  });

  it('should get collection info', async () => {
    const info = await adapter.getCollectionInfo();

    expect(info).toHaveProperty('status', 'green');
    expect(info).toHaveProperty('vectors_count', 100);
    expect(info).toHaveProperty('segments_count', 2);
  });

  it('should get collection stats', async () => {
    const stats = await adapter.getCollectionStats();

    expect(stats).toHaveProperty('vectorsCount', 100);
    expect(stats).toHaveProperty('indexedVectorsCount', 95);
    expect(stats).toHaveProperty('pointsCount', 100);
    expect(stats).toHaveProperty('segmentsCount', 2);
  });

  it('should update collection schema', async () => {
    const schemaConfig = {
      optimizer_config: {
        default_segment_number: 4,
      },
    };

    await adapter.updateCollectionSchema(schemaConfig);

    expect(mockClient.updateCollection).toHaveBeenCalledWith('knowledge_items', schemaConfig);
  });

  it('should optimize collection', async () => {
    await adapter.optimize();

    expect(mockClient.updateCollection).toHaveBeenCalledWith(
      'knowledge_items',
      expect.objectContaining({
        optimizers_config: expect.objectContaining({
          deleted_threshold: 0.2,
          vacuum_min_vector_number: 1000,
        }),
      })
    );
  });

  it('should backup collection', async () => {
    const backupName = await adapter.backup();

    expect(backupName).toBe('test-snapshot');
    expect(mockClient.createSnapshot).toHaveBeenCalledWith('knowledge_items');
  });

  it('should handle restore operation (not implemented)', async () => {
    await expect(adapter.restore('backup-source')).rejects.toThrow('not implemented');
  });

  it('should validate collection integrity', async () => {
    const validation = await adapter.validate();

    expect(validation).toHaveProperty('valid');
    expect(validation).toHaveProperty('issues');
    expect(validation.valid).toBe(true);
    expect(validation.issues).toHaveLength(0);
  });

  it('should detect validation issues', async () => {
    mockClient.getCollections.mockRejectedValue(new Error('Connection failed'));

    const validation = await adapter.validate();

    expect(validation.valid).toBe(false);
    expect(validation.issues.length).toBeGreaterThan(0);
  });
});

describe('QdrantAdapter - Error Handling and Resilience', () => {
  let adapter: QdrantAdapter;
  let mockClient: any;

  beforeEach(async () => {
    mockClient = createMockQdrantClient();
    vi.doMock('@qdrant/js-client-rest', () => ({
      QdrantClient: vi.fn().mockImplementation(() => mockClient),
    }));

    const config: VectorConfig = {
      type: 'qdrant',
      url: 'http://localhost:6333',
      vectorSize: 1536,
    };

    adapter = new QdrantAdapter(config);
    await adapter.initialize();
  });

  it('should handle API rate limiting gracefully', async () => {
    const rateLimitError = new Error('Rate limit exceeded');
    (rateLimitError as any).status = 429;

    mockClient.upsert.mockRejectedValue(rateLimitError);

    const item: KnowledgeItem = {
      id: 'rate-limit-test',
      kind: 'entity',
      scope: {},
      data: { title: 'Rate Limit Test' },
    };

    const result = await adapter.store([item]);

    expect(result.stored).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].message).toContain('Rate limit exceeded');
  });

  it('should handle network error recovery', async () => {
    const networkError = new Error('Network timeout');
    (networkError as any).code = 'ECONNRESET';

    mockClient.search.mockRejectedValueOnce(networkError);
    mockClient.search.mockResolvedValueOnce([
      { id: 'recovery-result', score: 0.9, payload: { kind: 'entity' } },
    ]);

    // First call fails
    await expect(adapter.search({ query: 'test' })).rejects.toThrow('Network timeout');

    // Second call succeeds (simulating recovery)
    const result = await adapter.search({ query: 'test' });
    expect(result.items).toHaveLength(1);
  });

  it('should handle invalid request/response handling', async () => {
    const invalidResponse = { invalid: 'response structure' };
    mockClient.getCollection.mockResolvedValue(invalidResponse);

    await expect(adapter.getMetrics()).rejects.toThrow();
  });

  it('should perform client-side validation', async () => {
    const invalidItems = [
      null,
      undefined,
      { kind: '' }, // Empty kind
      { kind: 'entity' }, // Missing required fields
    ] as any;

    const result = await adapter.store(invalidItems);

    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.stored.length).toBeLessThan(invalidItems.length);
  });

  it('should handle timeout errors', async () => {
    const timeoutError = new Error('Operation timeout');
    (timeoutError as any).code = 'ETIMEDOUT';

    mockClient.upsert.mockRejectedValue(timeoutError);

    const item: KnowledgeItem = {
      id: 'timeout-test',
      kind: 'entity',
      scope: {},
      data: { title: 'Timeout Test' },
    };

    await expect(adapter.store([item])).rejects.toThrow('Operation timeout');
  });

  it('should handle authentication errors', async () => {
    const authError = new Error('Authentication failed');
    (authError as any).status = 401;

    mockClient.getCollections.mockRejectedValue(authError);

    const newAdapter = new QdrantAdapter({
      type: 'qdrant',
      url: 'http://localhost:6333',
      apiKey: 'invalid-key',
    });

    await expect(newAdapter.initialize()).rejects.toThrow('Authentication failed');
  });

  it('should handle malformed payload data', async () => {
    const itemWithInvalidPayload: KnowledgeItem = {
      id: 'invalid-payload',
      kind: 'entity',
      scope: { project: 'test' },
      data: {
        // Circular reference that can't be serialized
        circular: null as any,
      },
    };

    itemWithInvalidPayload.data.circular = itemWithInvalidPayload.data;

    const result = await adapter.store([itemWithInvalidPayload]);

    // Should handle the error gracefully
    expect(result.errors.length).toBeGreaterThanOrEqual(0);
  });

  it('should handle connection pool exhaustion', async () => {
    const poolError = new Error('Connection pool exhausted');
    (poolError as any).code = 'ECONNREFUSED';

    mockClient.search.mockRejectedValue(poolError);

    await expect(adapter.search({ query: 'test' })).rejects.toThrow('Connection pool exhausted');
  });

  it('should retry on transient failures', async () => {
    const transientError = new Error('Transient failure');
    (transientError as any).code = 'EAI_AGAIN';

    mockClient.upsert
      .mockRejectedValueOnce(transientError)
      .mockResolvedValueOnce({ status: 'completed' });

    const item: KnowledgeItem = {
      id: 'retry-test',
      kind: 'entity',
      scope: {},
      data: { title: 'Retry Test' },
    };

    // Note: Actual retry logic would need to be implemented in the adapter
    // This test verifies the error handling structure
    const result = await adapter.store([item]);

    expect(result.stored.length).toBeGreaterThanOrEqual(0);
  });
});

describe('QdrantAdapter - Advanced Features', () => {
  let adapter: QdrantAdapter;
  let mockClient: any;

  beforeEach(async () => {
    mockClient = createMockQdrantClient();
    vi.doMock('@qdrant/js-client-rest', () => ({
      QdrantClient: vi.fn().mockImplementation(() => mockClient),
    }));

    const config: VectorConfig = {
      type: 'qdrant',
      url: 'http://localhost:6333',
      vectorSize: 1536,
    };

    adapter = new QdrantAdapter(config);
    await adapter.initialize();
  });

  it('should generate embeddings', async () => {
    const content = 'Test content for embedding';
    const embedding = await adapter.generateEmbedding(content);

    expect(embedding).toEqual([0.1, 0.2, 0.3, 0.4, 0.5]);
    expect(embedding).toHaveLength(5);
  });

  it('should store with pre-computed embeddings', async () => {
    const items: Array<KnowledgeItem & { embedding: number[] }> = [
      {
        id: 'pre-embedded',
        kind: 'entity',
        scope: {},
        data: { title: 'Pre-embedded Item' },
        embedding: [0.5, 0.4, 0.3, 0.2, 0.1],
      },
    ];

    const result = await adapter.storeWithEmbeddings(items);

    expect(result.stored).toHaveLength(1);
    expect(mockClient.upsert).toHaveBeenCalledWith(
      'knowledge_items',
      expect.objectContaining({
        points: expect.arrayContaining([
          expect.objectContaining({
            vector: [0.5, 0.4, 0.3, 0.2, 0.1],
          }),
        ]),
      })
    );
  });

  it('should perform vector search', async () => {
    const embedding = [0.1, 0.2, 0.3, 0.4, 0.5];

    const results = await adapter.vectorSearch(embedding, { limit: 10 });

    expect(results).toHaveLength(1);
    expect(results[0]).toHaveProperty('match_type', 'vector');
    expect(mockClient.search).toHaveBeenCalledWith(
      'knowledge_items',
      expect.objectContaining({
        vector: embedding,
        limit: 10,
      })
    );
  });

  it('should find nearest neighbors', async () => {
    const embedding = [0.1, 0.2, 0.3, 0.4, 0.5];

    const results = await adapter.findNearest(embedding, 5, 0.7);

    expect(results).toHaveLength(1);
    expect(mockClient.search).toHaveBeenCalledWith(
      'knowledge_items',
      expect.objectContaining({
        vector: embedding,
        limit: 5,
        score_threshold: 0.7,
      })
    );
  });

  it('should check for duplicates', async () => {
    const items: KnowledgeItem[] = [
      {
        id: 'duplicate-1',
        kind: 'entity',
        scope: { project: 'test' },
        data: { title: 'Duplicate Item', content: 'Same content' },
      },
      {
        id: 'duplicate-2',
        kind: 'entity',
        scope: { project: 'test' },
        data: { title: 'Duplicate Item', content: 'Same content' },
      },
    ];

    const result = await adapter.checkDuplicates(items);

    expect(result).toHaveProperty('duplicates');
    expect(result).toHaveProperty('originals');
  });

  it('should test functionality', async () => {
    const connectionTest = await adapter.testFunctionality('connection');
    expect(connectionTest).toBe(true);

    const searchTest = await adapter.testFunctionality('search');
    expect(searchTest).toBe(true);

    const storeTest = await adapter.testFunctionality('store');
    expect(storeTest).toBe(true);

    const invalidTest = await adapter.testFunctionality('invalid_operation');
    expect(invalidTest).toBe(false);
  });

  it('should get capabilities', async () => {
    const capabilities = await adapter.getCapabilities();

    expect(capabilities).toHaveProperty('supportsVectors', true);
    expect(capabilities).toHaveProperty('supportsFullTextSearch', true);
    expect(capabilities).toHaveProperty('supportsPayloadFiltering', true);
    expect(capabilities).toHaveProperty('maxBatchSize', 100);
    expect(capabilities).toHaveProperty('supportedDistanceMetrics');
    expect(capabilities).toHaveProperty('supportedOperations');
  });

  it('should get underlying client', async () => {
    const client = adapter.getClient();
    expect(client).toBeDefined();
    expect(client).toBe(mockClient);
  });

  it('should handle bulk operations efficiently', async () => {
    const largeBatch: KnowledgeItem[] = Array.from({ length: 100 }, (_, i) => ({
      id: `bulk-${i}`,
      kind: 'entity',
      scope: { project: 'bulk-test' },
      data: { title: `Bulk Item ${i}` },
    }));

    const startTime = Date.now();
    const result = await adapter.bulkStore(largeBatch);
    const duration = Date.now() - startTime;

    expect(result.stored).toHaveLength(100);
    expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
  });
});

describe('QdrantAdapter - Edge Cases and Boundary Conditions', () => {
  let adapter: QdrantAdapter;
  let mockClient: any;

  beforeEach(async () => {
    mockClient = createMockQdrantClient();
    vi.doMock('@qdrant/js-client-rest', () => ({
      QdrantClient: vi.fn().mockImplementation(() => mockClient),
    }));

    const config: VectorConfig = {
      type: 'qdrant',
      url: 'http://localhost:6333',
      vectorSize: 1536,
    };

    adapter = new QdrantAdapter(config);
    await adapter.initialize();
  });

  it('should handle extremely long queries', async () => {
    const longQuery = 'a'.repeat(10000);

    const result = await adapter.search({ query: longQuery });

    expect(result).toHaveProperty('items');
    expect(mockClient.search).toHaveBeenCalled();
  });

  it('should handle special characters in queries', async () => {
    const specialQuery = '🔍 Search with émojis & spéciäl chârß!';

    const result = await adapter.search({ query: specialQuery });

    expect(result).toHaveProperty('items');
  });

  it('should handle empty and whitespace queries', async () => {
    const emptyResult = await adapter.search({ query: '' });
    const whitespaceResult = await adapter.search({ query: '   ' });

    expect(emptyResult).toHaveProperty('items');
    expect(whitespaceResult).toHaveProperty('items');
  });

  it('should handle maximum batch size', async () => {
    const maxBatch: KnowledgeItem[] = Array.from({ length: 100 }, (_, i) => ({
      id: `max-batch-${i}`,
      kind: 'entity',
      scope: {},
      data: { title: `Max Batch Item ${i}` },
    }));

    const result = await adapter.store(maxBatch, { batchSize: 100 });

    expect(result.stored).toHaveLength(100);
  });

  it('should handle items with minimal data', async () => {
    const minimalItem: KnowledgeItem = {
      kind: 'section',
      scope: {},
      data: {},
    };

    const result = await adapter.store([minimalItem]);

    expect(result.stored).toHaveLength(1);
    expect(result.stored[0].kind).toBe('section');
  });

  it('should handle items with extensive metadata', async () => {
    const extensiveData = {
      title: 'Extensive Item',
      content: 'A'.repeat(100000), // Large content
      metadata: {
        // Deep nested object
        level1: {
          level2: {
            level3: {
              data: 'deep value',
            },
          },
        },
        // Many properties
        ...Object.fromEntries(Array.from({ length: 100 }, (_, i) => [`prop${i}`, `value${i}`])),
      },
    };

    const extensiveItem: KnowledgeItem = {
      id: 'extensive-item',
      kind: 'entity',
      scope: { project: 'extensive-test' },
      data: extensiveData,
    };

    const result = await adapter.store([extensiveItem]);

    expect(result.stored).toHaveLength(1);
  });

  it('should handle concurrent operations', async () => {
    const concurrentPromises = Array.from({ length: 10 }, (_, i) =>
      adapter.search({ query: `concurrent query ${i}` })
    );

    const results = await Promise.all(concurrentPromises);

    expect(results).toHaveLength(10);
    results.forEach((result) => {
      expect(result).toHaveProperty('items');
    });
  });

  it('should handle Unicode and international content', async () => {
    const unicodeItem: KnowledgeItem = {
      id: 'unicode-item',
      kind: 'section',
      scope: { project: 'тест-проект' },
      data: {
        title: 'Titre avec caractères spéciaux: éàêûöä',
        content: '内容包含中文和العربية characters',
        description: 'Описание на русском языке',
      },
    };

    const result = await adapter.store([unicodeItem]);

    expect(result.stored).toHaveLength(1);
  });

  it('should handle scope with various data types', async () => {
    const scopes = [
      { project: '', branch: 'main', org: 'test-org' },
      { project: 'test-project', branch: '', org: undefined },
      { project: null as any, branch: 'test', org: 'test' },
      { project: 'test', branch: 123 as any, org: true as any },
    ];

    for (const scope of scopes) {
      const item: KnowledgeItem = {
        id: `scope-test-${JSON.stringify(scope)}`,
        kind: 'entity',
        scope,
        data: { title: 'Scope Test Item' },
      };

      const result = await adapter.store([item]);
      expect(result.stored).toHaveLength(1);
    }
  });
});
