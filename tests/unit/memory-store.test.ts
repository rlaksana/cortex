import { describe, it, expect, beforeEach, vi } from 'vitest';
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
    }
  }
}));

describe('VectorDatabase - memory_store functionality', () => {
  let db: VectorDatabase;

  beforeEach(() => {
    db = new VectorDatabase();
  });

  describe('storeItems', () => {
    test('should store single item successfully', async () => {
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
    });

    test('should store batch items successfully', async () => {
      const items = global.testUtils.generateBatchItems(10);

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(10);
      expect(result.errors).toHaveLength(0);
      result.stored.forEach((item, index) => {
        expect(item).toHaveProperty('id');
        expect(item.content).toBe(`Test item ${index}`);
      });
    });

    test('should auto-generate UUIDs for items without IDs', async () => {
      const items = [{
        kind: 'entity',
        content: 'Test without ID'
      }];

      const result = await db.storeItems(items);

      expect(result.stored[0].id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
    });

    test('should handle items with complex metadata', async () => {
      const items = [{
        kind: 'decision',
        content: 'Technical decision',
        metadata: {
          alternatives: ['Option A', 'Option B'],
          rationale: 'Performance considerations',
          impact: 'High',
          stakeholders: ['Team A', 'Team B'],
          timeline: '2 weeks',
          budget: 50000,
          risks: ['Technical debt', 'Team availability']
        },
        scope: {
          project: 'test-project',
          branch: 'feature-branch',
          org: 'test-org'
        }
      }];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].metadata).toEqual(items[0].metadata);
      expect(result.stored[0].scope).toEqual(items[0].scope);
    });

    test('should handle all 16 knowledge types', async () => {
      const knowledgeTypes = [
        'entity', 'relation', 'observation', 'section', 'runbook',
        'change', 'issue', 'decision', 'todo', 'release_note',
        'ddl', 'pr_context', 'incident', 'release', 'risk', 'assumption'
      ];

      const items = knowledgeTypes.map(kind => ({
        kind,
        content: `Test ${kind} content`,
        metadata: { type: kind }
      }));

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(16);
      result.stored.forEach((item, index) => {
        expect(item.kind).toBe(knowledgeTypes[index]);
      });
    });

    test('should handle empty items array', async () => {
      const result = await db.storeItems([]);

      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(0);
    });

    test('should handle Unicode content', async () => {
      const items = [{
        kind: 'entity',
        content: 'Test with Unicode: 🧠 测试 ñoño العربية русский',
        metadata: {
          languages: ['emoji', 'chinese', 'spanish', 'arabic', 'russian']
        }
      }];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].content).toContain('🧠');
      expect(result.stored[0].content).toContain('测试');
    });

    test('should handle database errors gracefully', async () => {
      // Mock database error
      const mockClient = (db as any).client;
      mockClient.upsert.mockRejectedValue(new Error('Database connection failed'));

      const items = [{
        kind: 'entity',
        content: 'Test item'
      }];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toBe('Database connection failed');
    });

    test('should validate required fields', async () => {
      const items = [{
        kind: 'entity',
        // Missing required 'content' field
        metadata: { test: true }
      }];

      const result = await db.storeItems(items);

      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toBeDefined();
    });

    test('should handle very large content', async () => {
      const largeContent = 'A'.repeat(10000);
      const items = [{
        kind: 'entity',
        content: largeContent,
        metadata: { size: largeContent.length }
      }];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].content).toHaveLength(10000);
    });
  });

  describe('UUID generation', () => {
    test('should generate unique UUIDs', async () => {
      const items = Array(100).fill(null).map(() => ({
        kind: 'entity',
        content: 'Test item'
      }));

      const result = await db.storeItems(items);
      const ids = result.stored.map(item => item.id);
      const uniqueIds = new Set(ids);

      expect(ids).toHaveLength(100);
      expect(uniqueIds).toHaveLength(100);
    });

    test('should generate valid UUID v4 format', async () => {
      const items = [{
        kind: 'entity',
        content: 'Test UUID format'
      }];

      const result = await db.storeItems(items);
      const id = result.stored[0].id;

      // UUID v4 regex pattern
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      expect(id).toMatch(uuidRegex);
    });
  });
});
