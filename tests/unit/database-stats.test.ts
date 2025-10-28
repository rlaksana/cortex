import { describe, it, expect, beforeEach, vi } from 'vitest';
import { VectorDatabase } from '../../../src/index.js';

// Mock Qdrant client
vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class MockQdrantClient {
    constructor() {
      this.getCollections = vi.fn();
      this.createCollection = vi.fn();
      this.upsert = vi.fn();
      this.search = vi.fn();
      this.getCollection = vi.fn();
    }
  }
}));

// Mock environment variables for tests
vi.mock('dotenv', () => ({
  config: vi.fn()
}));

describe('VectorDatabase - database_stats functionality', () => {
  let db: VectorDatabase;
  let mockClient: any;

  beforeEach(() => {
    // Reset all mocks before each test
    vi.clearAllMocks();

    db = new VectorDatabase();

    // Get the mock client instance from the created database
    mockClient = (db as any).client;

    // Mock successful collection response for initialization
    mockClient.getCollections.mockResolvedValue({
      collections: [{ name: 'cortex-memory' }]
    });
  });

  describe('getStats', () => {
    test('should return accurate statistics for healthy database', async () => {
      mockClient.getCollection.mockResolvedValue({
        points_count: 42,
        status: 'green',
        optimizer_status: { ok: true },
        segments_count: 5,
        config: {
          vector_size: 1536,
          distance: 'Cosine',
          hnsw_config: { m: 16, ef_construct: 100 }
        },
        payload_schema: {
          properties: {
            kind: { type: 'keyword' },
            content: { type: 'text' }
          }
        }
      });

      const result = await db.getStats();

      expect(result.totalItems).toBe(42);
      expect(result.collectionInfo).toBeDefined();
      expect(result.collectionInfo.status).toBe('green');
      expect(result.collectionInfo.points_count).toBe(42);
      expect(result.collectionInfo.segments_count).toBe(5);
      expect(result.collectionInfo.config).toBeDefined();
    });

    test('should return zero stats for empty database', async () => {
      mockClient.getCollection.mockResolvedValue({
        points_count: 0,
        status: 'green',
        optimizer_status: { ok: true },
        segments_count: 1,
        config: {
          vector_size: 1536,
          distance: 'Cosine'
        }
      });

      const result = await db.getStats();

      expect(result.totalItems).toBe(0);
      expect(result.collectionInfo.points_count).toBe(0);
      expect(result.collectionInfo.status).toBe('green');
    });

    test('should handle database connection errors', async () => {
      mockClient.getCollection.mockRejectedValue(new Error('Database connection failed'));

      const result = await db.getStats();

      expect(result.totalItems).toBe(0);
      expect(result.collectionInfo).toBeNull();
    });

    test('should return consistent stats format', async () => {
      mockClient.getCollection.mockResolvedValue({
        points_count: 100,
        status: 'green'
      });

      const result = await db.getStats();

      expect(result).toHaveProperty('totalItems');
      expect(result).toHaveProperty('collectionInfo');
      expect(typeof result.totalItems).toBe('number');
    });
  });
});
