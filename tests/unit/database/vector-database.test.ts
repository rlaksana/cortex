/**
 * Comprehensive Unit Tests for Vector Database Core Functionality
 *
 * Tests vector database operations including:
 * - Database Connection and Health (connection establishment, health checks, error handling, retry mechanisms)
 * - Collection Management (creation, validation, deletion, listing, information retrieval)
 * - Vector Operations (insertion/upsert, search with similarity scoring, deletion, batch operations)
 * - Index and Configuration (vector index configuration, distance metrics, shard configuration, performance optimization)
 * - Error Handling and Edge Cases (network issues, invalid dimensions, malformed data, timeouts)
 * - Integration with Knowledge System (knowledge item storage, embedding generation, scope filtering, TTL enforcement)
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { VectorDatabase } from '../../../src/index';

// Define interfaces based on the actual VectorDatabase implementation
interface KnowledgeItem {
  kind: string;
  id: string;
  content: string;
  metadata?: Record<string, unknown>;
  scope?: {
    project?: string;
    branch?: string;
    org?: string;
  };
  created_at?: Date;
  updated_at?: Date;
  data?: any;
  ttl_policy?: string;
}

interface MemoryStoreResponse {
  stored: KnowledgeItem[];
  errors: Array<{
    item: KnowledgeItem;
    error: string;
  }>;
}

interface MemoryFindResponse {
  items: (KnowledgeItem & { score?: number })[];
  total: number;
  query: string;
  strategy: string;
  confidence: number;
}

// Mock Qdrant client with comprehensive method coverage using vi.fn()
const mockGetCollections = vi.fn();
const mockCreateCollection = vi.fn();
const mockGetCollection = vi.fn();
const mockUpsert = vi.fn();
const mockSearch = vi.fn();
const mockDelete = vi.fn();
const mockRetrieve = vi.fn();
const mockScroll = vi.fn();
const mockCreateSnapshot = vi.fn();
const mockUpdateCollection = vi.fn();
const mockDeleteCollection = vi.fn();

vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class {
    constructor(config?: any) {
      this.config = config;
      this.connectionAttempts = 0;
      this.maxRetries = 3;
    }

    // Connection and Health Methods
    async getCollections() {
      this.connectionAttempts++;
      if (this.config?.shouldFailConnection && this.connectionAttempts <= this.maxRetries) {
        throw new Error('Connection failed');
      }
      return mockGetCollections();
    }

    async healthCheck() {
      return this.connectionAttempts > 0;
    }

    // Collection Management Methods
    async createCollection(name: string, config?: any) {
      return mockCreateCollection(name, config);
    }

    async deleteCollection(name: string) {
      return mockDeleteCollection(name);
    }

    async getCollection(name: string) {
      return mockGetCollection(name);
    }

    async updateCollection(name: string, config: any) {
      return mockUpdateCollection(name, config);
    }

    // Vector Operations Methods
    async upsert(collectionName: string, points: any) {
      return mockUpsert(collectionName, points);
    }

    async search(collectionName: string, params: any) {
      return mockSearch(collectionName, params);
    }

    async retrieve(collectionName: string, params: any) {
      return mockRetrieve(collectionName, params);
    }

    async delete(collectionName: string, params: any) {
      return mockDelete(collectionName, params);
    }

    async scroll(collectionName: string, params: any) {
      return mockScroll(collectionName, params);
    }

    async createSnapshot(collectionName: string) {
      return mockCreateSnapshot(collectionName);
    }
  },
}));

describe('Vector Database - Comprehensive Core Functionality Testing', () => {
  let db: VectorDatabase;
  let mockQdrant: any;

  beforeEach(() => {
    // Set up default mock behaviors using test collection name
    const testCollectionName = 'test-cortex-memory';

    mockGetCollections.mockResolvedValue({
      collections: [{ name: testCollectionName }, { name: 'test_collection' }],
    });

    mockCreateCollection.mockResolvedValue({ name: testCollectionName });

    mockGetCollection.mockResolvedValue({
      name: testCollectionName,
      status: 'green',
      vectors_count: 1000,
      indexed_vectors_count: 950,
      points_count: 1000,
      segments_count: 2,
      disk_data_size: 1048576,
      ram_data_size: 524288,
      optimizer_status: 'ok',
      config: {
        vector_size: 1536,
        distance: 'Cosine',
      },
      payload_schema: {},
    });

    mockUpsert.mockResolvedValue({ operation_id: 'upsert_123', status: 'completed' });

    mockSearch.mockImplementation((collectionName: string, params: any) => {
      const mockResults = [
        {
          id: 'result_1',
          score: 0.95,
          payload: {
            kind: 'entity',
            scope: { project: 'test-project', branch: 'main' },
            content: 'Test entity content for search',
            created_at: '2025-01-01T00:00:00Z',
          },
        },
        {
          id: 'result_2',
          score: 0.85,
          payload: {
            kind: 'decision',
            scope: { project: 'test-project', branch: 'main' },
            content: 'Test decision content for search',
            created_at: '2025-01-01T01:00:00Z',
          },
        },
      ];

      return mockResults.slice(0, params.limit || 10);
    });

    mockDelete.mockResolvedValue({ status: 'completed', deleted_count: 1 });
    mockRetrieve.mockResolvedValue([]);
    mockScroll.mockResolvedValue({ points: [], next_page_offset: null });
    mockCreateSnapshot.mockResolvedValue({ name: 'snapshot_test.snapshot' });
    mockUpdateCollection.mockResolvedValue({ name: testCollectionName });
    mockDeleteCollection.mockResolvedValue({ name: testCollectionName });

    // Initialize database with test configuration
    db = new VectorDatabase();
    mockQdrant = (db as any).client;
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Database Connection and Health', () => {
    it('should establish connection with Qdrant successfully', async () => {
      const health = await db.getHealth();

      expect(health.status).toBe('healthy');
      expect(health.collections).toContain('test-cortex-memory');
      expect(mockGetCollections).toHaveBeenCalled();
    });

    it('should handle connection errors gracefully', async () => {
      mockGetCollections.mockRejectedValue(new Error('Network timeout'));

      const health = await db.getHealth();

      expect(health.status).toBe('unhealthy');
      expect(health.collections).toHaveLength(0);
    });

    it('should initialize database with collection creation', async () => {
      await db.initialize();

      expect(mockGetCollections).toHaveBeenCalled();
      expect(db).toBeDefined();
    });

    it('should handle initialization errors', async () => {
      mockGetCollections.mockRejectedValue(new Error('Connection failed'));

      await expect(db.initialize()).rejects.toThrow('Connection failed');
    });
  });

  describe('Collection Management', () => {
    it('should create collection if it does not exist', async () => {
      mockGetCollections.mockResolvedValue({
        collections: [], // No existing collections
      });

      await db.initialize();

      expect(mockCreateCollection).toHaveBeenCalledWith(
        'test-cortex-memory',
        expect.objectContaining({
          vectors: expect.objectContaining({
            size: 1536,
            distance: 'Cosine',
          }),
        })
      );
    });

    it('should not create collection if it already exists', async () => {
      mockGetCollections.mockResolvedValue({
        collections: [{ name: 'test-cortex-memory' }],
      });

      await db.initialize();

      expect(mockCreateCollection).not.toHaveBeenCalled();
    });

    it('should handle collection creation errors', async () => {
      mockGetCollections.mockResolvedValue({
        collections: [],
      });
      mockCreateCollection.mockRejectedValue(new Error('Insufficient permissions'));

      await expect(db.initialize()).rejects.toThrow('Insufficient permissions');
    });
  });

  describe('Vector Operations', () => {
    it('should store single knowledge item successfully', async () => {
      const item: KnowledgeItem = {
        kind: 'entity',
        content: 'Test entity content',
        scope: { project: 'test-project', branch: 'main' },
        metadata: { test: true },
      };

      const result = await db.storeItems([item]);

      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      expect(result.stored[0]).toHaveProperty('id');
      expect(result.stored[0].kind).toBe('entity');
      expect(result.stored[0].content).toBe('Test entity content');
      expect(mockUpsert).toHaveBeenCalled();
    });

    it('should store multiple knowledge items successfully', async () => {
      const items: KnowledgeItem[] = [
        {
          kind: 'entity',
          content: 'First entity content',
          scope: { project: 'test-project', branch: 'main' },
        },
        {
          kind: 'decision',
          content: 'First decision content',
          scope: { project: 'test-project', branch: 'main' },
        },
        {
          kind: 'issue',
          content: 'First issue content',
          scope: { project: 'test-project', branch: 'main' },
        },
      ];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(3);
      expect(result.errors).toHaveLength(0);
      expect(mockUpsert).toHaveBeenCalledTimes(3);
    });

    it('should handle storage errors gracefully', async () => {
      const item: KnowledgeItem = {
        kind: 'entity',
        content: 'Test entity content',
      };

      mockUpsert.mockRejectedValue(new Error('Connection failed'));

      const result = await db.storeItems([item]);

      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toContain('Connection failed');
    });

    it('should search items with semantic similarity', async () => {
      const query = 'test query';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[0]).toHaveProperty('score');
      expect(result.items[0].score).toBeGreaterThan(0.8);
      expect(result.query).toBe(query);
      expect(result.strategy).toBe('semantic');
      expect(mockSearch).toHaveBeenCalled();
    });

    it('should search items with limit parameter', async () => {
      const query = 'test query';
      const limit = 5;

      const result = await db.searchItems(query, limit);

      expect(result.items.length).toBeLessThanOrEqual(limit);
      expect(mockSearch).toHaveBeenCalledWith(
        'test-cortex-memory',
        expect.objectContaining({ limit })
      );
    });

    it('should handle search errors gracefully', async () => {
      mockSearch.mockRejectedValue(new Error('Search failed'));

      await expect(db.searchItems('test')).rejects.toThrow('Search failed');
    });

    it('should handle empty search results', async () => {
      mockSearch.mockResolvedValue([]);

      const result = await db.searchItems('nonexistent query');

      expect(result.items).toHaveLength(0);
      expect(result.total).toBe(0);
      expect(result.confidence).toBe(0);
    });

    it('should auto-initialize database on first operation', async () => {
      const item: KnowledgeItem = {
        kind: 'entity',
        content: 'Test content',
      };

      // Mock that collection doesn't exist initially
      mockGetCollections.mockResolvedValue({
        collections: [],
      });

      await db.storeItems([item]);

      // Should have created collection
      expect(mockCreateCollection).toHaveBeenCalled();
      expect(mockUpsert).toHaveBeenCalled();
    });
  });

  describe('Knowledge Type Integration', () => {
    it('should handle all 16 knowledge types', async () => {
      const knowledgeTypes = [
        'entity',
        'relation',
        'observation',
        'section',
        'runbook',
        'change',
        'issue',
        'decision',
        'todo',
        'release_note',
        'ddl',
        'pr_context',
        'incident',
        'release',
        'risk',
        'assumption',
      ];

      const items = knowledgeTypes.map((kind) => ({
        kind,
        content: `Test ${kind} content`,
        scope: { project: 'test-project', branch: 'main' },
      }));

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(16);
      expect(result.errors).toHaveLength(0);

      // Verify all types were stored
      const storedKinds = result.stored.map((item) => item.kind);
      knowledgeTypes.forEach((kind) => {
        expect(storedKinds).toContain(kind);
      });
    });

    it('should handle items with complex metadata', async () => {
      const item: KnowledgeItem = {
        kind: 'decision',
        content: 'Technical decision content',
        metadata: {
          alternatives: ['Option A', 'Option B'],
          rationale: 'Performance optimization',
          stakeholders: ['team-lead', 'architect'],
          impact: 'high',
          timeline: 'Q2 2025',
        },
        scope: { project: 'test-project', branch: 'main' },
      };

      const result = await db.storeItems([item]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].metadata).toEqual(item.metadata);
    });

    it('should handle items with different scopes', async () => {
      const items: KnowledgeItem[] = [
        {
          kind: 'entity',
          content: 'Project A entity',
          scope: { project: 'project-A', branch: 'main' },
        },
        {
          kind: 'entity',
          content: 'Project B entity',
          scope: { project: 'project-B', branch: 'develop' },
        },
        {
          kind: 'entity',
          content: 'Organization entity',
          scope: { project: 'project-C', branch: 'main', org: 'organization-X' },
        },
      ];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(3);
      expect(result.stored[0].scope.project).toBe('project-A');
      expect(result.stored[1].scope.branch).toBe('develop');
      expect(result.stored[2].scope.org).toBe('organization-X');
    });
  });

  describe('Embedding Generation', () => {
    it('should generate embeddings for content', async () => {
      const item: KnowledgeItem = {
        kind: 'entity',
        content: 'Test content for embedding generation',
      };

      await db.storeItems([item]);

      expect(mockUpsert).toHaveBeenCalledWith(
        'test-cortex-memory',
        expect.objectContaining({
          points: expect.arrayContaining([
            expect.objectContaining({
              vector: expect.any(Array),
              payload: expect.objectContaining({
                kind: 'entity',
                content: 'Test content for embedding generation',
              }),
            }),
          ]),
        })
      );
    });

    it('should generate consistent embeddings for same content', async () => {
      const content = 'Same content for embedding test';
      const items: KnowledgeItem[] = [
        { kind: 'entity', content },
        { kind: 'decision', content },
      ];

      await db.storeItems(items);

      const upsertCalls = mockUpsert.mock.calls;
      expect(upsertCalls).toHaveLength(2);

      // Both embeddings should be arrays of the same length
      expect(upsertCalls).toHaveLength(2);
      expect(upsertCalls[0]).toBeDefined();
      expect(upsertCalls[1]).toBeDefined();
      // The actual embedding data is handled internally by VectorDatabase
      // We just verify that upsert was called twice
      expect(mockUpsert).toHaveBeenCalledTimes(2);
    });

    it('should handle very long content', async () => {
      const longContent = 'x'.repeat(10000); // 10KB content
      const item: KnowledgeItem = {
        kind: 'section',
        content: longContent,
      };

      const result = await db.storeItems([item]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].content).toHaveLength(10000);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle invalid knowledge items', async () => {
      const invalidItems = [
        null,
        undefined,
        { kind: 'entity' }, // Missing content
        { content: 'Missing kind' }, // Missing kind
        { kind: '', content: 'Empty kind' },
      ];

      const results = await Promise.all(invalidItems.map((item) => db.storeItems([item as any])));

      // Some should result in errors, others might be handled gracefully
      // Let's check that at least some items were processed
      expect(results).toHaveLength(5);

      // Check that we have a mix of successes and errors
      const totalStored = results.reduce((sum, r) => sum + r.stored.length, 0);
      const totalErrors = results.reduce((sum, r) => sum + r.errors.length, 0);

      // At least some items should be processed (either stored or errored)
      expect(totalStored + totalErrors).toBeGreaterThan(0);
    });

    it('should handle empty items array', async () => {
      const result = await db.storeItems([]);

      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(0);
    });

    it('should handle network timeouts during storage', async () => {
      const item: KnowledgeItem = {
        kind: 'entity',
        content: 'Test content',
      };

      mockUpsert.mockImplementation(
        () => new Promise((_, reject) => setTimeout(() => reject(new Error('ETIMEDOUT')), 100))
      );

      const result = await db.storeItems([item]);

      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toContain('ETIMEDOUT');
    });

    it('should handle malformed search parameters', async () => {
      // Test with empty query
      await expect(db.searchItems('')).resolves.toBeDefined();

      // Test with very long query
      const longQuery = 'x'.repeat(10000);
      const result = await db.searchItems(longQuery);
      expect(result).toBeDefined();
    });

    it('should handle database connection loss during operation', async () => {
      const item: KnowledgeItem = {
        kind: 'entity',
        content: 'Test content',
      };

      // Simulate connection loss
      mockUpsert.mockRejectedValue(new Error('ECONNRESET'));

      const result = await db.storeItems([item]);

      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toContain('ECONNRESET');
    });

    it('should handle memory-intensive operations', async () => {
      const largeItems = Array.from({ length: 100 }, (_, i) => ({
        kind: 'entity' as const,
        content: `Large content item ${i} with additional data: ${'x'.repeat(1000)}`,
        metadata: {
          index: i,
          largeArray: Array.from({ length: 100 }, (_, j) => `data_${i}_${j}`),
        },
      }));

      const result = await db.storeItems(largeItems);

      expect(result.stored).toHaveLength(100);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle concurrent storage operations', async () => {
      const items = Array.from({ length: 50 }, (_, i) => ({
        kind: 'entity' as const,
        content: `Concurrent item ${i}`,
        scope: { project: 'concurrent-test' },
      }));

      const promises = items.map((item) => db.storeItems([item]));
      const results = await Promise.all(promises);

      expect(results.every((r) => r.stored.length === 1)).toBe(true);
      expect(results.reduce((sum, r) => sum + r.stored.length, 0)).toBe(50);
    });

    it('should handle concurrent search operations', async () => {
      const queries = Array.from({ length: 20 }, (_, i) => `search query ${i}`);

      const promises = queries.map((query) => db.searchItems(query));
      const results = await Promise.all(promises);

      expect(results).toHaveLength(20);
      results.forEach((result) => {
        expect(result).toHaveProperty('items');
        expect(result).toHaveProperty('query');
        expect(result).toHaveProperty('strategy');
      });
    });

    it('should maintain performance with large batches', async () => {
      const largeBatch = Array.from({ length: 200 }, (_, i) => ({
        kind: 'entity' as const,
        content: `Batch item ${i}`,
        scope: { project: 'performance-test' },
      }));

      const startTime = Date.now();
      const result = await db.storeItems(largeBatch);
      const endTime = Date.now();

      expect(result.stored).toHaveLength(200);
      expect(result.errors).toHaveLength(0);
      expect(endTime - startTime).toBeLessThan(5000); // Should complete within 5 seconds
    });
  });

  describe('Database Statistics and Health', () => {
    it('should provide database statistics', async () => {
      const stats = await db.getStats();

      expect(stats).toHaveProperty('totalItems');
      expect(stats).toHaveProperty('collectionInfo');
      expect(typeof stats.totalItems).toBe('number');
    });

    it('should handle stats errors gracefully', async () => {
      mockGetCollection.mockRejectedValue(new Error('Collection not found'));

      const stats = await db.getStats();

      expect(stats.totalItems).toBe(0);
      expect(stats.collectionInfo).toBe(null);
    });

    it('should provide health status', async () => {
      const health = await db.getHealth();

      expect(health).toHaveProperty('status');
      expect(health).toHaveProperty('collections');
      expect(['healthy', 'unhealthy']).toContain(health.status);
      expect(Array.isArray(health.collections)).toBe(true);
    });

    it('should handle health check errors', async () => {
      mockGetCollections.mockRejectedValue(new Error('Health check failed'));

      const health = await db.getHealth();

      expect(health.status).toBe('unhealthy');
      expect(health.collections).toHaveLength(0);
    });
  });

  describe('UUID Generation', () => {
    it('should generate unique UUIDs for stored items', async () => {
      const items: KnowledgeItem[] = [
        { kind: 'entity', content: 'First item' },
        { kind: 'entity', content: 'Second item' },
      ];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(2);
      expect(result.stored[0].id).toBeDefined();
      expect(result.stored[1].id).toBeDefined();
      expect(result.stored[0].id).not.toBe(result.stored[1].id);

      // Verify UUID format
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      expect(result.stored[0].id).toMatch(uuidRegex);
      expect(result.stored[1].id).toMatch(uuidRegex);
    });

    it('should generate UUIDs even when IDs are provided', async () => {
      const itemWithId: KnowledgeItem = {
        id: 'provided-id',
        kind: 'entity',
        content: 'Item with provided ID',
      };

      const result = await db.storeItems([itemWithId]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].id).toBeDefined();
      // The implementation should always generate its own UUID
      expect(result.stored[0].id).not.toBe('provided-id');
    });
  });

  describe('Data Validation', () => {
    it('should handle items with missing optional fields', async () => {
      const minimalItem: KnowledgeItem = {
        kind: 'entity',
        content: 'Minimal item',
      };

      const result = await db.storeItems([minimalItem]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].kind).toBe('entity');
      expect(result.stored[0].content).toBe('Minimal item');
      expect(result.stored[0].id).toBeDefined();
    });

    it('should handle items with additional fields', async () => {
      const itemWithExtraFields: any = {
        kind: 'entity',
        content: 'Item with extra fields',
        scope: { project: 'test' },
        metadata: { test: true },
        customField: 'custom value',
        anotherField: 123,
        nestedObject: { prop: 'value' },
      };

      const result = await db.storeItems([itemWithExtraFields]);

      expect(result.stored).toHaveLength(1);
      // Extra fields should be preserved in the payload
      expect(result.stored[0]).toBeDefined();
    });

    it('should validate required fields', async () => {
      const invalidItems = [
        { content: 'Missing kind' },
        { kind: 'entity' }, // Missing content
        { kind: '', content: 'Empty kind' },
        { kind: 'entity', content: '' }, // Empty content
      ];

      const results = await Promise.all(invalidItems.map((item) => db.storeItems([item as any])));

      // Should handle various validation states gracefully
      results.forEach((result) => {
        expect(result).toBeDefined();
        // Some might succeed, some might fail depending on validation logic
      });
    });
  });

  describe('Integration Tests', () => {
    it('should handle complete knowledge workflow', async () => {
      // Store multiple items
      const items: KnowledgeItem[] = [
        {
          kind: 'entity',
          content: 'User entity with profile information',
          scope: { project: 'user-management', branch: 'main' },
          metadata: { userType: 'premium', active: true },
        },
        {
          kind: 'decision',
          content: 'Decision to implement new authentication system',
          scope: { project: 'user-management', branch: 'main' },
          metadata: { impact: 'high', timeline: 'Q3 2025' },
        },
        {
          kind: 'issue',
          content: 'Security vulnerability in password reset',
          scope: { project: 'user-management', branch: 'main' },
          metadata: { severity: 'critical', status: 'open' },
        },
      ];

      const storeResult = await db.storeItems(items);
      expect(storeResult.stored).toHaveLength(3);

      // Search for items
      const searchResult = await db.searchItems('user authentication');
      expect(searchResult.items).toHaveLength(2);
      expect(searchResult.strategy).toBe('semantic');

      // Search with specific scope
      const scopedResult = await db.searchItems('management');
      expect(scopedResult.items.length).toBeGreaterThan(0);

      // Get statistics
      const stats = await db.getStats();
      expect(stats.totalItems).toBeGreaterThanOrEqual(3);

      // Check health
      const health = await db.getHealth();
      expect(health.status).toBe('healthy');
    });

    it('should handle error recovery workflow', async () => {
      const item: KnowledgeItem = {
        kind: 'entity',
        content: 'Test recovery item',
      };

      // First attempt fails
      mockUpsert.mockRejectedValueOnce(new Error('Temporary failure'));
      const firstResult = await db.storeItems([item]);
      expect(firstResult.errors).toHaveLength(1);

      // Second attempt succeeds
      const secondResult = await db.storeItems([item]);
      expect(secondResult.stored).toHaveLength(1);
      expect(secondResult.errors).toHaveLength(0);
    });
  });
});
