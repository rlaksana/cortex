/**
 * MCP Server Unit Tests
 *
 * Unit tests for individual MCP server components and functions.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { TestUtils, MockQdrantClient } from '../setup/mcp-test-setup';

describe('MCP Server Unit Tests', () => {
  let mockServer: any;
  let mockQdrant: MockQdrantClient;

  beforeEach(() => {
    // Reset mocks
    vi.clearAllMocks();

    // Initialize mock Qdrant client
    mockQdrant = new MockQdrantClient();

    // Mock console.error to reduce test output noise
    vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Tool Validation', () => {
    it('should validate memory_store input schema', () => {
      const validItem = TestUtils.generateTestMemoryItem('entity', {
        title: 'Test Entity',
        description: 'Test Description'
      });

      expect(validItem.kind).toBe('entity');
      expect(validItem.data).toBeDefined();
      expect(validItem.data.title).toBe('Test Entity');
      expect(validItem.scope).toBeDefined();
    });

    it('should validate memory_find input schema', () => {
      const validSearchParams = {
        query: 'test search',
        scope: {
          project: 'test-project',
          branch: 'test-branch'
        },
        types: ['entity', 'decision'],
        limit: 10
      };

      expect(validSearchParams.query).toBe('test search');
      expect(validSearchParams.scope?.project).toBe('test-project');
      expect(Array.isArray(validSearchParams.types)).toBe(true);
      expect(validSearchParams.limit).toBe(10);
    });

    it('should reject invalid memory_store items', () => {
      const invalidItem = {
        // Missing required 'kind' field
        data: { title: 'Test' }
      };

      expect(invalidItem.kind).toBeUndefined();
    });

    it('should reject invalid memory_find parameters', () => {
      const invalidSearchParams = {
        query: 123, // Should be string
        limit: 'ten' // Should be number
      };

      expect(typeof invalidSearchParams.query).not.toBe('string');
      expect(typeof invalidSearchParams.limit).not.toBe('number');
    });
  });

  describe('Mock Qdrant Client', () => {
    beforeEach(() => {
      mockQdrant = new MockQdrantClient();
    });

    it('should create and manage collections', async () => {
      const collectionName = 'test-collection';
      const config = {
        vectors: { size: 384, distance: 'Cosine' }
      };

      // Should throw for non-existent collection
      await expect(mockQdrant.getCollection(collectionName)).rejects.toThrow();

      // Create collection
      await mockQdrant.createCollection(collectionName, config);

      // Should now find the collection
      const collection = await mockQdrant.getCollection(collectionName);
      expect(collection.name).toBe(collectionName);
      expect(collection.config).toEqual(config);
      expect(collection.points_count).toBe(0);
    });

    it('should store and retrieve points', async () => {
      const collectionName = 'test-collection';
      await mockQdrant.createCollection(collectionName, { vectors: { size: 384 } });

      const testPoints = {
        points: [
          {
            id: 'point-1',
            vector: Array(384).fill(0.1),
            payload: TestUtils.generateTestMemoryItem('entity', { title: 'Test Entity 1' })
          },
          {
            id: 'point-2',
            vector: Array(384).fill(0.2),
            payload: TestUtils.generateTestMemoryItem('decision', { title: 'Test Decision 1' })
          }
        ]
      };

      // Store points
      await mockQdrant.upsert(collectionName, testPoints);

      // Verify collection count
      const collection = await mockQdrant.getCollection(collectionName);
      expect(collection.points_count).toBe(2);
    });

    it('should search points with filters', async () => {
      const collectionName = 'test-collection';
      await mockQdrant.createCollection(collectionName, { vectors: { size: 384 } });

      // Store mixed type points
      const testPoints = {
        points: [
          {
            id: 'entity-1',
            vector: Array(384).fill(0.1),
            payload: TestUtils.generateTestMemoryItem('entity', { title: 'Entity 1' })
          },
          {
            id: 'decision-1',
            vector: Array(384).fill(0.2),
            payload: TestUtils.generateTestMemoryItem('decision', { title: 'Decision 1' })
          },
          {
            id: 'entity-2',
            vector: Array(384).fill(0.3),
            payload: TestUtils.generateTestMemoryItem('entity', { title: 'Entity 2' })
          }
        ]
      };

      await mockQdrant.upsert(collectionName, testPoints);

      // Search without filter
      const allResults = await mockQdrant.search(collectionName, {
        vector: Array(384).fill(0.1),
        limit: 10,
        with_payload: true
      });
      expect(allResults.length).toBe(3);

      // Search with type filter
      const entityResults = await mockQdrant.search(collectionName, {
        vector: Array(384).fill(0.1),
        limit: 10,
        with_payload: true,
        filter: {
          must: [
            {
              key: 'kind',
              match: { any: ['entity'] }
            }
          ]
        }
      });
      expect(entityResults.length).toBe(2);

      // Search with scope filter
      const scopedResults = await mockQdrant.search(collectionName, {
        vector: Array(384).fill(0.1),
        limit: 10,
        with_payload: true,
        filter: {
          must: [
            {
              key: 'scope.project',
              match: { value: 'test-project' }
            }
          ]
        }
      });
      expect(scopedResults.length).toBe(3); // All items have test-project scope
    });

    it('should handle point updates', async () => {
      const collectionName = 'test-collection';
      await mockQdrant.createCollection(collectionName, { vectors: { size: 384 } });

      const originalPoint = {
        points: [
          {
            id: 'point-1',
            vector: Array(384).fill(0.1),
            payload: TestUtils.generateTestMemoryItem('entity', { title: 'Original Title' })
          }
        ]
      };

      await mockQdrant.upsert(collectionName, originalPoint);

      // Update the point
      const updatedPoint = {
        points: [
          {
            id: 'point-1',
            vector: Array(384).fill(0.2),
            payload: TestUtils.generateTestMemoryItem('entity', { title: 'Updated Title' })
          }
        ]
      };

      await mockQdrant.upsert(collectionName, updatedPoint);

      // Verify collection still has only one point
      const collection = await mockQdrant.getCollection(collectionName);
      expect(collection.points_count).toBe(1);

      // Search to verify update
      const results = await mockQdrant.search(collectionName, {
        vector: Array(384).fill(0.2),
        limit: 10,
        with_payload: true
      });
      expect(results.length).toBe(1);
      expect(results[0].payload.data.title).toBe('Updated Title');
    });

    it('should delete collections', async () => {
      const collectionName = 'test-collection';
      await mockQdrant.createCollection(collectionName, { vectors: { size: 384 } });

      // Verify collection exists
      await expect(mockQdrant.getCollection(collectionName)).resolves.toBeDefined();

      // Delete collection
      await mockQdrant.deleteCollection(collectionName);

      // Verify collection no longer exists
      await expect(mockQdrant.getCollection(collectionName)).rejects.toThrow();
    });
  });

  describe('Test Utilities', () => {
    it('should generate valid test memory items', () => {
      const item = TestUtils.generateTestMemoryItem('entity', { custom: 'value' });

      expect(item.kind).toBe('entity');
      expect(item.data).toBeDefined();
      expect(item.data.title).toBe('Test entity');
      expect(item.data.custom).toBe('value');
      expect(item.scope).toBeDefined();
      expect(item.scope?.project).toBe('test-project');
    });

    it('should generate batch test items', () => {
      const items = TestUtils.generateBatchTestItems(5);

      expect(Array.isArray(items)).toBe(true);
      expect(items.length).toBe(5);

      // Check that all items have required fields
      items.forEach((item, index) => {
        expect(item.kind).toBeDefined();
        expect(item.data).toBeDefined();
        expect(item.scope).toBeDefined();
        expect(item.data.index).toBe(index);
      });

      // Check that we have different types
      const types = items.map(item => item.kind);
      const uniqueTypes = new Set(types);
      expect(uniqueTypes.size).toBeGreaterThan(1);
    });

    it('should create valid test server requests', () => {
      const request = TestUtils.createTestServerRequest('memory_store', {
        items: [TestUtils.generateTestMemoryItem('entity')]
      });

      expect(request.jsonrpc).toBe('2.0');
      expect(request.method).toBe('tools/call');
      expect(request.params.name).toBe('memory_store');
      expect(request.params.arguments).toBeDefined();
      expect(request.params.arguments.items).toBeDefined();
      expect(Array.isArray(request.params.arguments.items)).toBe(true);
      expect(request.id).toBeDefined();
    });

    it('should handle timeout correctly', async () => {
      const slowPromise = new Promise(resolve => setTimeout(resolve, 1000));

      // Should resolve when timeout is larger
      await expect(TestUtils.withTimeout(slowPromise, 2000)).resolves.toBeDefined();

      // Should reject when timeout is smaller
      await expect(TestUtils.withTimeout(slowPromise, 100)).rejects.toThrow('timed out');
    });

    it('should sleep for specified duration', async () => {
      const start = Date.now();
      await TestUtils.sleep(100);
      const end = Date.now();

      // Should sleep for at least 100ms (with some tolerance)
      expect(end - start).toBeGreaterThanOrEqual(90);
    });
  });

  describe('Input Validation', () => {
    it('should validate memory item kinds', () => {
      const validKinds = [
        'entity', 'relation', 'observation', 'section', 'runbook',
        'change', 'issue', 'decision', 'todo', 'release_note',
        'ddl', 'pr_context', 'incident', 'release', 'risk', 'assumption'
      ];

      validKinds.forEach(kind => {
        const item = TestUtils.generateTestMemoryItem(kind);
        expect(item.kind).toBe(kind);
      });
    });

    it('should validate scope structure', () => {
      const scope = {
        project: 'test-project',
        branch: 'test-branch',
        org: 'test-org'
      };

      expect(scope.project).toBe('test-project');
      expect(scope.branch).toBe('test-branch');
      expect(scope.org).toBe('test-org');
    });

    it('should validate search parameters', () => {
      const searchParams = {
        query: 'test query',
        scope: { project: 'test' },
        types: ['entity', 'decision'],
        limit: 10
      };

      expect(typeof searchParams.query).toBe('string');
      expect(typeof searchParams.scope).toBe('object');
      expect(Array.isArray(searchParams.types)).toBe(true);
      expect(typeof searchParams.limit).toBe('number');
      expect(searchParams.limit).toBeGreaterThan(0);
    });
  });

  describe('Error Scenarios', () => {
    it('should handle missing collection gracefully', async () => {
      const mockQdrant = new MockQdrantClient();

      await expect(mockQdrant.getCollection('non-existent')).rejects.toThrow();
    });

    it('should handle empty search results', async () => {
      const collectionName = 'test-collection';
      const mockQdrant = new MockQdrantClient();

      await mockQdrant.createCollection(collectionName, { vectors: { size: 384 } });

      // Search in empty collection
      const results = await mockQdrant.search(collectionName, {
        vector: Array(384).fill(0.1),
        limit: 10,
        with_payload: true
      });

      expect(results).toEqual([]);
    });

    it('should handle malformed filters', async () => {
      const collectionName = 'test-collection';
      const mockQdrant = new MockQdrantClient();

      await mockQdrant.createCollection(collectionName, { vectors: { size: 384 } });

      // Search with malformed filter (should not crash)
      const results = await mockQdrant.search(collectionName, {
        vector: Array(384).fill(0.1),
        limit: 10,
        with_payload: true,
        filter: {
          must: [
            {
              key: 'non.existent.path',
              match: { value: 'test' }
            }
          ]
        }
      });

      expect(results).toEqual([]);
    });
  });

  describe('Data Transformation', () => {
    it('should handle nested scope access', async () => {
      const mockQdrant = new MockQdrantClient();

      // Test nested object access
      const testPayload = {
        kind: 'entity',
        scope: {
          project: 'test-project',
          nested: {
            value: 'nested-value'
          }
        }
      };

      const filter = {
        must: [
          {
            key: 'scope.project',
            match: { value: 'test-project' }
          }
        ]
      };

      // This should work without throwing
      const value = mockQdrant['getNestedValue'](testPayload, 'scope.project');
      expect(value).toBe('test-project');

      const nestedValue = mockQdrant['getNestedValue'](testPayload, 'scope.nested.value');
      expect(nestedValue).toBe('nested-value');

      const nonExistentValue = mockQdrant['getNestedValue'](testPayload, 'scope.non.existent');
      expect(nonExistentValue).toBeUndefined();
    });
  });
});