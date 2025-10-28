import { describe, it, expect, beforeEach, vi } from 'vitest';
import { VectorDatabase } from '../../src/index';

// Mock Qdrant client
vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class {
    constructor() {
      this.getCollections = vi.fn();
      this.createCollection = vi.fn();
      this.upsert = vi.fn();
      this.search = vi.fn();
      this.getCollection = vi.fn();
    }
  }
}));

describe('VectorDatabase - database_health functionality', () => {
  let db: VectorDatabase;

  beforeEach(() => {
    db = new VectorDatabase();
  });

  describe('getHealth', () => {
    test('should return healthy status when connected', async () => {
      const mockClient = (db as any).client;
      mockClient.getCollections.mockResolvedValue({
        collections: [
          { name: 'collection1' },
          { name: 'collection2' },
          { name: 'test-collection' }
        ]
      });

      const result = await db.getHealth();

      expect(result.status).toBe('healthy');
      expect(result.collections).toHaveLength(3);
      expect(result.collections).toContain('collection1');
      expect(result.collections).toContain('collection2');
      expect(result.collections).toContain('test-collection');
    });

    test('should return unhealthy status when connection fails', async () => {
      const mockClient = (db as any).client;
      mockClient.getCollections.mockRejectedValue(new Error('Connection failed'));

      const result = await db.getHealth();

      expect(result.status).toBe('unhealthy');
      expect(result.collections).toEqual([]);
    });

    test('should handle empty collections list', async () => {
      const mockClient = (db as any).client;
      mockClient.getCollections.mockResolvedValue({
        collections: []
      });

      const result = await db.getHealth();

      expect(result.status).toBe('healthy');
      expect(result.collections).toEqual([]);
    });

    test('should handle network timeout', async () => {
      const mockClient = (db as any).client;
      mockClient.getCollections.mockRejectedValue(new Error('Timeout'));

      const result = await db.getHealth();

      expect(result.status).toBe('unhealthy');
      expect(result.collections).toEqual([]);
    });

    test('should handle authentication errors', async () => {
      const mockClient = (db as any).client;
      mockClient.getCollections.mockRejectedValue(new Error('Authentication failed'));

      const result = await db.getHealth();

      expect(result.status).toBe('unhealthy');
    });

    test('should return consistent health status format', async () => {
      const mockClient = (db as any).client;
      mockClient.getCollections.mockResolvedValue({
        collections: [{ name: 'test-collection' }]
      });

      const result = await db.getHealth();

      expect(result).toHaveProperty('status');
      expect(result).toHaveProperty('collections');
      expect(typeof result.status).toBe('string');
      expect(Array.isArray(result.collections)).toBe(true);
    });

    test('should handle malformed response from Qdrant', async () => {
      const mockClient = (db as any).client;
      mockClient.getCollections.mockResolvedValue({ invalid: 'response' });

      const result = await db.getHealth();

      expect(result.status).toBe('unhealthy');
      expect(result.collections).toEqual([]);
    });

    test('should complete health check quickly', async () => {
      const mockClient = (db as any).client;
      mockClient.getCollections.mockResolvedValue({
        collections: [{ name: 'test-collection' }]
      });

      const startTime = Date.now();
      const result = await db.getHealth();
      const duration = Date.now() - startTime;

      expect(result.status).toBe('healthy');
      expect(duration).toBeLessThan(500); // Should complete within 500ms
    });

    test('should handle concurrent health checks', async () => {
      const mockClient = (db as any).client;
      mockClient.getCollections.mockResolvedValue({
        collections: [{ name: 'test-collection' }]
      });

      const promises = Array(3).fill(null).map(() => db.getHealth());
      const results = await Promise.all(promises);

      expect(results).toHaveLength(3);
      results.forEach(result => {
        expect(result.status).toBe('healthy');
        expect(result.collections).toEqual(['test-collection']);
      });
    });
  });

  describe('health check reliability', () => {
    test('should maintain consistent results across multiple calls', async () => {
      const mockClient = (db as any).client;
      mockClient.getCollections.mockResolvedValue({
        collections: [
          { name: 'collection1' },
          { name: 'collection2' }
        ]
      });

      const result1 = await db.getHealth();
      const result2 = await db.getHealth();

      expect(result1).toEqual(result2);
      expect(result1.status).toBe('healthy');
      expect(result1.collections).toEqual(['collection1', 'collection2']);
    });

    test('should recover from temporary connection issues', async () => {
      const mockClient = (db as any).client;
      
      // First call fails
      mockClient.getCollections.mockRejectedValueOnce(new Error('Temporary failure'));
      const result1 = await db.getHealth();
      expect(result1.status).toBe('unhealthy');

      // Second call succeeds
      mockClient.getCollections.mockResolvedValue({
        collections: [{ name: 'test-collection' }]
      });
      const result2 = await db.getHealth();
      expect(result2.status).toBe('healthy');
    });
  });
});
