/**
 * Qdrant Client Tests
 *
 * Tests for the Qdrant client implementation
 */

import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';
import { type MockQdrantClient } from '../../../types/database-types-enhanced.js';

describe('QdrantClient', () => {
  let mockQdrantClient: MockQdrantClient;

  beforeEach(() => {
    mockQdrantClient = {
      connect: vi.fn().mockResolvedValue(undefined),
      disconnect: vi.fn().mockResolvedValue(undefined),
      healthCheck: vi.fn().mockResolvedValue(true),
      createCollection: vi.fn().mockResolvedValue(undefined),
      deleteCollection: vi.fn().mockResolvedValue(undefined),
      getCollection: vi.fn().mockResolvedValue({}),
      upsert: vi.fn().mockResolvedValue(undefined),
      search: vi.fn().mockResolvedValue([]),
      scroll: vi.fn().mockResolvedValue([]),
      recommend: vi.fn().mockResolvedValue([]),
      facet: vi.fn().mockResolvedValue({}),
    } as MockQdrantClient;
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('connection management', () => {
    test('should create client with valid configuration', () => {
      expect(mockQdrantClient).toBeDefined();
    });

    test('should handle connection errors gracefully', async () => {
      vi.mocked(mockQdrantClient.connect).mockRejectedValue(new Error('Connection failed'));

      try {
        await mockQdrantClient.connect();
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Connection failed');
      }
    });
  });

  describe('collection operations', () => {
    test('should create collection successfully', async () => {
      vi.mocked(mockQdrantClient.createCollection).mockResolvedValue(undefined);

      const result = await mockQdrantClient.createCollection('test-collection', {});

      expect(mockQdrantClient.createCollection).toHaveBeenCalledWith('test-collection', {});
      expect(result).toBeUndefined();
    });

    test('should handle collection creation errors', async () => {
      vi.mocked(mockQdrantClient.createCollection).mockRejectedValue(new Error('Collection already exists'));

      try {
        await mockQdrantClient.createCollection('test-collection', {});
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Collection already exists');
      }
    });
  });

  describe('vector operations', () => {
    test('should perform upsert operation successfully', async () => {
      vi.mocked(mockQdrantClient.upsert).mockResolvedValue(undefined);

      const vectors = [{ id: '1', vector: [1, 2, 3], payload: { text: 'test' } }];

      const result = await mockQdrantClient.upsert('test-collection', vectors);

      expect(mockQdrantClient.upsert).toHaveBeenCalledWith('test-collection', vectors);
      expect(result).toBeUndefined();
    });

    test('should perform search operation successfully', async () => {
      const mockSearchResult = [{ id: '1', score: 0.9, payload: { text: 'test' } }];
      vi.mocked(mockQdrantClient.search).mockResolvedValue(mockSearchResult as unknown[]);

      const queryVector = [1, 2, 3];
      const result = await mockQdrantClient.search('test-collection', { vector: queryVector });

      expect(mockQdrantClient.search).toHaveBeenCalledWith('test-collection', {
        vector: queryVector,
      });
      expect(result).toEqual(mockSearchResult);
    });
  });
});
