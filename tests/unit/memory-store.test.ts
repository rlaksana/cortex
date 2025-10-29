/**
 * Standardized Unit Tests for Memory Store
 *
 * Tests memory store functionality including:
 * - Knowledge item storage and retrieval
 * - Batch operations
 * - Search functionality
 * - Error handling
 * - Performance considerations
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { VectorDatabase } from '../../src/index';

// Mock Qdrant client
vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class {
    constructor() {
      this.getCollections = vi.fn().mockResolvedValue({
        collections: [{ name: 'test-collection' }]
      });
      this.createCollection = vi.fn().mockResolvedValue(undefined);
      this.upsert = vi.fn().mockResolvedValue(undefined);
      this.search = vi.fn().mockResolvedValue([]);
      this.getCollection = vi.fn().mockResolvedValue({
        points_count: 0,
        status: 'green'
      });
      this.delete = vi.fn().mockResolvedValue({ status: 'completed' });
      this.count = vi.fn().mockResolvedValue({ count: 0 });
      this.healthCheck = vi.fn().mockResolvedValue(true);
    }
  }
}));

describe('VectorDatabase - memory_store functionality', () => {
  let db: VectorDatabase;
  let mockQdrant: any;

  beforeEach(() => {
    db = new VectorDatabase();
    // Get the mock client instance
    mockQdrant = (db as any).client;
  });

  describe('storeItems', () => {
    it('should store single item successfully', async () => {
      const items = [{
        kind: 'entity',
        content: 'Test entity',
        metadata: { test: true }
      }];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      expect(result.stored[0]).toHaveProperty('id');
      expect(result.stored[0].kind).toBe('entity');
      expect(result.stored[0].content).toBe('Test entity');

      // Verify Qdrant client was called
      expect(mockQdrant.upsert).toHaveBeenCalled();
    });

    it('should store batch items successfully', async () => {
      const items = Array.from({ length: 10 }, (_, i) => ({
        kind: 'entity',
        content: `Test item ${i}`,
        metadata: { batch: true, index: i }
      }));

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(10);
      expect(result.errors).toHaveLength(0);
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(10); // Called once per item
    });

    it('should handle storage errors gracefully', async () => {
      const items = [{
        kind: 'entity',
        content: 'Test item'
      }];

      // Mock upsert to throw an error
      mockQdrant.upsert.mockRejectedValue(new Error('Connection failed'));

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toContain('Connection failed');
    });

    it('should handle invalid items', async () => {
      const items = [
        null,
        undefined,
        {},
        { kind: 'invalid-kind' }
      ];

      const result = await db.storeItems(items as any);

      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.stored.length).toBeLessThan(items.length);
    });
  });

  describe('searchItems', () => {
    beforeEach(() => {
      // Setup search mock
      mockQdrant.search.mockResolvedValue([
        {
          id: 'test-id-1',
          score: 0.9,
          payload: {
            kind: 'entity',
            content: 'Test content 1',
            metadata: { test: true }
          }
        },
        {
          id: 'test-id-2',
          score: 0.8,
          payload: {
            kind: 'observation',
            content: 'Test content 2',
            metadata: { test: true }
          }
        }
      ]);
    });

    it('should find items by query', async () => {
      const query = 'test query';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[0].content).toBe('Test content 1');
      expect(result.items[1].content).toBe('Test content 2');
      expect(mockQdrant.search).toHaveBeenCalled();
    });

    it('should handle search errors gracefully', async () => {
      mockQdrant.search.mockRejectedValue(new Error('Search failed'));

      await expect(db.searchItems('test')).rejects.toThrow('Search failed');
    });

    it('should handle empty results', async () => {
      mockQdrant.search.mockResolvedValue([]);

      const result = await db.searchItems('nonexistent');

      expect(result.items).toHaveLength(0);
      expect(result.total).toBe(0);
    });
  });

  describe('getStats', () => {
    beforeEach(() => {
      mockQdrant.getCollection.mockResolvedValue({
        points_count: 100,
        status: 'green',
        optimizer_status: 'ok'
      });
    });

    it('should return collection statistics', async () => {
      const stats = await db.getStats();

      expect(stats.totalItems).toBe(100);
      expect(stats.collectionInfo.status).toBe('green');
      expect(mockQdrant.getCollection).toHaveBeenCalled();
    });

    it('should handle stats errors gracefully', async () => {
      mockQdrant.getCollection.mockRejectedValue(new Error('Stats failed'));

      const stats = await db.getStats();

      expect(stats.totalItems).toBe(0);
      expect(stats.collectionInfo).toBe(null);
    });
  });

  describe('getHealth', () => {
    it('should return healthy status when connection works', async () => {
      mockQdrant.getCollections.mockResolvedValue({
        collections: [{ name: 'test-collection' }]
      });

      const health = await db.getHealth();

      expect(health.status).toBe('healthy');
      expect(health.collections).toContain('test-collection');
      expect(mockQdrant.getCollections).toHaveBeenCalled();
    });

    it('should return unhealthy status when connection fails', async () => {
      mockQdrant.getCollections.mockRejectedValue(new Error('Connection failed'));

      const health = await db.getHealth();

      expect(health.status).toBe('unhealthy');
      expect(health.collections).toHaveLength(0);
    });
  });

  describe('Knowledge Type Operations', () => {
    it('should handle all 16 knowledge types', async () => {
      const knowledgeTypes = [
        'entity', 'relation', 'observation', 'section', 'runbook',
        'change', 'issue', 'decision', 'todo', 'release_note',
        'ddl', 'pr_context', 'incident', 'release', 'risk', 'assumption'
      ];

      for (const kind of knowledgeTypes) {
        const item = { kind, content: `Test ${kind} content` };
        const result = await db.storeItems([item]);

        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].kind).toBe(kind);
      }
    });

    it('should handle various knowledge types with metadata', async () => {
      const items = [
        {
          kind: 'decision',
          content: 'Technical decision',
          metadata: { alternatives: ['Option A', 'Option B'], rationale: 'Performance' }
        },
        {
          kind: 'observation',
          content: 'System observation',
          metadata: { metrics: { cpu: 80, memory: 60 } }
        },
        {
          kind: 'runbook',
          content: 'Operational procedure',
          metadata: { steps: ['Step 1', 'Step 2'], owner: 'ops-team' }
        }
      ];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(3);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle network timeouts', async () => {
      const items = [{
        kind: 'entity',
        content: 'Test item'
      }];

      // Mock timeout error
      mockQdrant.upsert.mockRejectedValue(new Error('ETIMEDOUT'));

      const result = await db.storeItems(items);

      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toContain('ETIMEDOUT');
    });

    it('should handle missing required fields in items', async () => {
      const items = [
        { content: 'Missing kind' },
        { kind: 'entity' }, // Missing content
        { kind: 'entity', content: 'test' } // Valid item
      ];

      const result = await db.storeItems(items as any);

      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.stored.length).toBeLessThan(items.length);
    });

    it('should handle very large content', async () => {
      const largeContent = 'x'.repeat(10000); // 10KB content
      const item = {
        kind: 'entity',
        content: largeContent,
        metadata: { size: largeContent.length }
      };

      const result = await db.storeItems([item]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].content).toHaveLength(10000);
    });
  });

  describe('Batch Operations', () => {
    it('should handle mixed valid and invalid items in batch', async () => {
      const items = [
        { kind: 'entity', content: 'Valid item 1' },
        null,
        { kind: 'entity', content: 'Valid item 2' },
        undefined,
        { invalid: 'item' },
        { kind: 'entity', content: 'Valid item 3' }
      ];

      const result = await db.storeItems(items as any);

      expect(result.stored).toHaveLength(3); // 3 valid items
      expect(result.errors).toHaveLength(3); // 3 invalid items
    });
  });
});