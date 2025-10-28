import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  storeEntity,
  softDeleteEntity,
  getEntity,
  searchEntities
} from '../../../src/services/knowledge/entity';

// Mock the UnifiedDatabaseLayer with a proper class structure
const mockDb = {
  initialize: vi.fn().mockResolvedValue(undefined),
  find: vi.fn(),
  create: vi.fn(),
  update: vi.fn(),
  fullTextSearch: vi.fn(),
};

// Create a proper mock class that can be instantiated
class MockUnifiedDatabaseLayer {
  initialize = mockDb.initialize;
  find = mockDb.find;
  create = mockDb.create;
  update = mockDb.update;
  fullTextSearch = mockDb.fullTextSearch;
}

vi.mock('../../../src/db/unified-database-layer-v2', () => ({
  UnifiedDatabaseLayer: MockUnifiedDatabaseLayer,
}));

describe('Entity Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('storeEntity', () => {
    const mockData = {
      entity_type: 'component',
      name: 'UserService',
      data: { version: '1.0.0', status: 'active' }
    };
    const mockScope = { project: 'test-project', org: 'test-org' };

    it('should store new entity successfully', async () => {
      // Arrange
      const expectedId = 'entity-uuid-123';
      mockDb.find.mockResolvedValue([]); // No existing entity
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeEntity(mockData, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockDb.initialize).toHaveBeenCalled();
      expect(mockDb.find).toHaveBeenCalledWith('knowledge_entity', {
        content_hash: expect.any(String),
        deleted_at: null,
      });
      expect(mockDb.create).toHaveBeenCalledWith('knowledge_entity', {
        entity_type: mockData.entity_type,
        name: mockData.name,
        data: mockData.data,
        content_hash: expect.any(String),
        scope: mockScope,
        created_at: expect.any(String),
        updated_at: expect.any(String),
      });
    });

    it('should return existing entity ID if content hash matches', async () => {
      // Arrange
      const existingId = 'existing-entity-uuid';
      mockDb.find
        .mockResolvedValueOnce([{ id: existingId }]) // First call finds by content hash
        .mockResolvedValue([]); // Second call for name check (shouldn't reach)

      // Act
      const result = await storeEntity(mockData, mockScope);

      // Assert
      expect(result).toBe(existingId);
      expect(mockDb.create).not.toHaveBeenCalled();
      expect(mockDb.update).not.toHaveBeenCalled();
    });

    it('should update existing entity if same entity_type and name exist', async () => {
      // Arrange
      const existingId = 'existing-entity-uuid';
      mockDb.find
        .mockResolvedValueOnce([]) // First call: no content hash match
        .mockResolvedValueOnce([{ id: existingId }]); // Second call: same name found
      mockDb.update.mockResolvedValue({ id: existingId, rowCount: 1 });

      // Act
      const result = await storeEntity(mockData, mockScope);

      // Assert
      expect(result).toBe(existingId);
      expect(mockDb.update).toHaveBeenCalledWith('knowledge_entity',
        expect.objectContaining({
          entity_type: mockData.entity_type,
          name: mockData.name,
          data: mockData.data,
        }),
        { id: existingId }
      );
      expect(mockDb.create).not.toHaveBeenCalled();
    });

    it('should generate consistent content hash for same data', async () => {
      // Arrange
      mockDb.find.mockResolvedValue([]);
      mockDb.create.mockResolvedValue({ id: 'entity-123' });

      // Act
      await storeEntity(mockData, mockScope);
      const firstCall = mockDb.find.mock.calls[0];

      mockDb.find.mockClear();
      await storeEntity(mockData, mockScope);
      const secondCall = mockDb.find.mock.calls[0];

      // Assert
      expect(firstCall[1].content_hash).toBe(secondCall[1].content_hash);
    });

    it('should handle database initialization errors', async () => {
      // Arrange
      mockDb.initialize.mockRejectedValue(new Error('Database connection failed'));

      // Act & Assert
      await expect(storeEntity(mockData, mockScope)).rejects.toThrow(
        'Entity storage failed: Database connection failed'
      );
    });

    it('should handle database creation errors', async () => {
      // Arrange
      mockDb.find.mockResolvedValue([]);
      mockDb.create.mockRejectedValue(new Error('Insert failed'));

      // Act & Assert
      await expect(storeEntity(mockData, mockScope)).rejects.toThrow(
        'Entity storage failed: Insert failed'
      );
    });

    it('should handle complex nested data structures', async () => {
      // Arrange
      const complexData = {
        entity_type: 'configuration',
        name: 'ComplexConfig',
        data: {
          nested: {
            array: [1, 2, 3],
            object: { key: 'value' },
            boolean: true,
            nullValue: null,
            undefinedValue: undefined
          },
          metadata: {
            tags: ['tag1', 'tag2'],
            version: { major: 1, minor: 2, patch: 3 }
          }
        }
      };
      mockDb.find.mockResolvedValue([]);
      mockDb.create.mockResolvedValue({ id: 'complex-entity-id' });

      // Act
      const result = await storeEntity(complexData, mockScope);

      // Assert
      expect(result).toBe('complex-entity-id');
      expect(mockDb.create).toHaveBeenCalledWith('knowledge_entity',
        expect.objectContaining({
          data: complexData.data
        }),
        undefined
      );
    });

    it('should handle empty scope', async () => {
      // Arrange
      mockDb.find.mockResolvedValue([]);
      mockDb.create.mockResolvedValue({ id: 'entity-no-scope' });

      // Act
      const result = await storeEntity(mockData, {});

      // Assert
      expect(result).toBe('entity-no-scope');
      expect(mockDb.create).toHaveBeenCalledWith('knowledge_entity',
        expect.objectContaining({
          scope: {}
        }),
        undefined
      );
    });

    it('should handle unicode content in entity data', async () => {
      // Arrange
      const unicodeData = {
        entity_type: 'localized',
        name: 'Entité Française 🧠',
        data: { description: '测试 中文 ñoño العربية' }
      };
      mockDb.find.mockResolvedValue([]);
      mockDb.create.mockResolvedValue({ id: 'unicode-entity-id' });

      // Act
      const result = await storeEntity(unicodeData, mockScope);

      // Assert
      expect(result).toBe('unicode-entity-id');
      expect(mockDb.create).toHaveBeenCalledWith('knowledge_entity',
        expect.objectContaining({
          name: 'Entité Française 🧠',
          data: { description: '测试 中文 ñoño العربية' }
        }),
        undefined
      );
    });

    it('should validate required entity_type field', async () => {
      // Arrange
      const invalidData = {
        name: 'TestEntity',
        data: { test: true }
        // Missing entity_type
      };

      // Act & Assert - The service should handle this gracefully
      // The exact behavior depends on implementation, but it shouldn't crash
      await expect(storeEntity(invalidData as any, mockScope)).rejects.toThrow();
    });

    it('should validate required name field', async () => {
      // Arrange
      const invalidData = {
        entity_type: 'component',
        data: { test: true }
        // Missing name
      };

      // Act & Assert
      await expect(storeEntity(invalidData as any, mockScope)).rejects.toThrow();
    });

    it('should handle very large entity data', async () => {
      // Arrange
      const largeData = {
        entity_type: 'large',
        name: 'LargeEntity',
        data: { content: 'A'.repeat(100000) } // 100KB of data
      };
      mockDb.find.mockResolvedValue([]);
      mockDb.create.mockResolvedValue({ id: 'large-entity-id' });

      // Act
      const result = await storeEntity(largeData, mockScope);

      // Assert
      expect(result).toBe('large-entity-id');
    });
  });

  describe('softDeleteEntity', () => {
    const entityId = 'entity-to-delete';

    it('should soft delete entity successfully', async () => {
      // Arrange
      mockDb.update.mockResolvedValue({ rowCount: 1 });

      // Act
      const result = await softDeleteEntity(entityId);

      // Assert
      expect(result).toBe(true);
      expect(mockDb.update).toHaveBeenCalledWith('knowledge_entity',
        { deleted_at: expect.any(String) },
        { id: entityId, deleted_at: null }
      );
    });

    it('should return false when entity not found', async () => {
      // Arrange
      mockDb.update.mockResolvedValue({ rowCount: 0 });

      // Act
      const result = await softDeleteEntity(entityId);

      // Assert
      expect(result).toBe(false);
    });

    it('should handle database errors during deletion', async () => {
      // Arrange
      mockDb.update.mockRejectedValue(new Error('Delete failed'));

      // Act & Assert
      await expect(softDeleteEntity(entityId)).rejects.toThrow(
        'Entity soft delete failed: Delete failed'
      );
    });

    it('should handle empty entity ID', async () => {
      // Act & Assert
      await expect(softDeleteEntity('')).rejects.toThrow();
      await expect(softDeleteEntity(null as any)).rejects.toThrow();
      await expect(softDeleteEntity(undefined as any)).rejects.toThrow();
    });
  });

  describe('getEntity', () => {
    const entityId = 'entity-to-get';
    const mockScope = { project: 'test-project' };

    it('should get entity by ID successfully', async () => {
      // Arrange
      const mockEntity = {
        id: entityId,
        entity_type: 'component',
        name: 'UserService',
        data: { version: '1.0.0' },
        scope: mockScope,
        created_at: '2023-01-01T00:00:00Z',
        updated_at: '2023-01-01T00:00:00Z',
      };
      mockDb.find.mockResolvedValue([mockEntity]);

      // Act
      const result = await getEntity(entityId, mockScope);

      // Assert
      expect(result).toEqual({
        id: entityId,
        data: {
          entity_type: mockEntity.entity_type,
          name: mockEntity.name,
          data: mockEntity.data,
        },
        scope: mockEntity.scope,
        created_at: mockEntity.created_at,
        updated_at: mockEntity.updated_at,
      });
      expect(mockDb.find).toHaveBeenCalledWith('knowledge_entity', {
        id: entityId,
        deleted_at: null,
        'scope->>project': 'test-project',
      });
    });

    it('should return null when entity not found', async () => {
      // Arrange
      mockDb.find.mockResolvedValue([]);

      // Act
      const result = await getEntity(entityId);

      // Assert
      expect(result).toBeNull();
    });

    it('should get entity without scope filter', async () => {
      // Arrange
      const mockEntity = {
        id: entityId,
        entity_type: 'component',
        name: 'UserService',
        data: { version: '1.0.0' },
        scope: mockScope,
        created_at: '2023-01-01T00:00:00Z',
        updated_at: '2023-01-01T00:00:00Z',
      };
      mockDb.find.mockResolvedValue([mockEntity]);

      // Act
      const result = await getEntity(entityId);

      // Assert
      expect(result).not.toBeNull();
      expect(mockDb.find).toHaveBeenCalledWith('knowledge_entity', {
        id: entityId,
        deleted_at: null,
      });
    });

    it('should handle multiple scope filters', async () => {
      // Arrange
      const multiScope = { project: 'test-project', org: 'test-org', branch: 'main' };
      mockDb.find.mockResolvedValue([]);

      // Act
      await getEntity(entityId, multiScope);

      // Assert
      expect(mockDb.find).toHaveBeenCalledWith('knowledge_entity', {
        id: entityId,
        deleted_at: null,
        'scope->>project': 'test-project',
        'scope->>org': 'test-org',
        'scope->>branch': 'main',
      });
    });

    it('should handle database errors during retrieval', async () => {
      // Arrange
      mockDb.find.mockRejectedValue(new Error('Database query failed'));

      // Act & Assert
      await expect(getEntity(entityId)).rejects.toThrow(
        'Entity retrieval failed: Database query failed'
      );
    });

    it('should handle malformed entity data from database', async () => {
      // Arrange
      const malformedEntity = {
        id: entityId,
        // Missing required fields
        entity_type: null,
        name: undefined,
        data: 'not an object',
      };
      mockDb.find.mockResolvedValue([malformedEntity]);

      // Act & Assert
      // The service should handle this gracefully
      const result = await getEntity(entityId);
      expect(result).toBeDefined(); // Should not crash
    });
  });

  describe('searchEntities', () => {
    const query = 'user service';
    const filters = {
      entity_type: 'component',
      scope: { project: 'test-project' },
      limit: 10,
    };

    it('should search entities with query and filters', async () => {
      // Arrange
      const mockSearchResults = [
        {
          id: 'entity-1',
          entity_type: 'component',
          name: 'UserService',
          data: { version: '1.0.0' },
          scope: filters.scope,
          created_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
          rank: 1,
          score: 0.95,
          highlight: '<mark>User</mark> Service',
        },
      ];
      mockDb.fullTextSearch.mockResolvedValue(mockSearchResults);

      // Act
      const result = await searchEntities(query, filters);

      // Assert
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({
        id: 'entity-1',
        data: {
          entity_type: 'component',
          name: 'UserService',
          data: { version: '1.0.0' },
        },
        scope: filters.scope,
        created_at: '2023-01-01T00:00:00Z',
        updated_at: '2023-01-01T00:00:00Z',
        rank: 1,
        score: 0.95,
        highlight: '<mark>User</mark> Service',
      });
      expect(mockDb.fullTextSearch).toHaveBeenCalledWith('knowledge_entity', {
        query: query.trim(),
        config: 'english',
        weighting: { D: 0.1, C: 0.2, B: 0.4, A: 1.0 },
        highlight: true,
        snippet_size: 150,
        max_results: filters.limit,
      });
    });

    it('should search entities without query (filter-based)', async () => {
      // Arrange
      const mockFilterResults = [
        {
          id: 'entity-2',
          entity_type: 'component',
          name: 'AuthService',
          data: { version: '2.0.0' },
          scope: filters.scope,
          created_at: '2023-01-02T00:00:00Z',
          updated_at: '2023-01-02T00:00:00Z',
        },
      ];
      mockDb.find.mockResolvedValue(mockFilterResults);

      // Act
      const result = await searchEntities('', filters);

      // Assert
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({
        id: 'entity-2',
        data: {
          entity_type: 'component',
          name: 'AuthService',
          data: { version: '2.0.0' },
        },
        scope: filters.scope,
        created_at: '2023-01-02T00:00:00Z',
        updated_at: '2023-01-02T00:00:00Z',
      });
      expect(mockDb.find).toHaveBeenCalledWith('knowledge_entity', {
        deleted_at: null,
        entity_type: filters.entity_type,
        'scope->>project': 'test-project',
      }, {
        take: filters.limit,
        orderBy: { updated_at: 'desc' },
      });
    });

    it('should search with default filters', async () => {
      // Arrange
      mockDb.fullTextSearch.mockResolvedValue([]);

      // Act
      await searchEntities(query);

      // Assert
      expect(mockDb.fullTextSearch).toHaveBeenCalledWith('knowledge_entity', {
        query: query.trim(),
        config: 'english',
        weighting: { D: 0.1, C: 0.2, B: 0.4, A: 1.0 },
        highlight: true,
        snippet_size: 150,
        max_results: 50, // Default limit
      });
    });

    it('should handle empty query with whitespace', async () => {
      // Arrange
      mockDb.find.mockResolvedValue([]);

      // Act
      await searchEntities('   ');

      // Assert
      expect(mockDb.find).toHaveBeenCalled(); // Should use filter-based search
      expect(mockDb.fullTextSearch).not.toHaveBeenCalled();
    });

    it('should handle default limit when not specified', async () => {
      // Arrange
      mockDb.find.mockResolvedValue([]);

      // Act
      await searchEntities('', { entity_type: 'component' });

      // Assert
      expect(mockDb.find).toHaveBeenCalledWith('knowledge_entity',
        expect.any(Object),
        { take: 50, orderBy: { updated_at: 'desc' } }
      );
    });

    it('should handle full-text search errors', async () => {
      // Arrange
      mockDb.fullTextSearch.mockRejectedValue(new Error('FTS failed'));

      // Act & Assert
      await expect(searchEntities(query, filters)).rejects.toThrow(
        'Entity search failed: FTS failed'
      );
    });

    it('should handle filter search errors', async () => {
      // Arrange
      mockDb.find.mockRejectedValue(new Error('Filter search failed'));

      // Act & Assert
      await expect(searchEntities('', filters)).rejects.toThrow(
        'Entity search failed: Filter search failed'
      );
    });

    it('should handle search with only entity_type filter', async () => {
      // Arrange
      mockDb.fullTextSearch.mockResolvedValue([]);

      // Act
      await searchEntities(query, { entity_type: 'service' });

      // Assert - Should call FTS but filter results will be applied at database level
      expect(mockDb.fullTextSearch).toHaveBeenCalled();
    });

    it('should handle search with only scope filter', async () => {
      // Arrange
      const scopeOnly = { scope: { project: 'test' } };
      mockDb.fullTextSearch.mockResolvedValue([]);

      // Act
      await searchEntities(query, scopeOnly);

      // Assert
      expect(mockDb.fullTextSearch).toHaveBeenCalled();
    });

    it('should handle large search results', async () => {
      // Arrange
      const largeLimit = 1000;
      const mockResults = Array(largeLimit).fill(null).map((_, index) => ({
        id: `entity-${index}`,
        entity_type: 'component',
        name: `Component${index}`,
        data: { index },
        scope: {},
        created_at: '2023-01-01T00:00:00Z',
        updated_at: '2023-01-01T00:00:00Z',
      }));
      mockDb.fullTextSearch.mockResolvedValue(mockResults);

      // Act
      const result = await searchEntities(query, { limit: largeLimit });

      // Assert
      expect(result).toHaveLength(largeLimit);
      expect(mockDb.fullTextSearch).toHaveBeenCalledWith('knowledge_entity',
        expect.objectContaining({
          max_results: largeLimit,
        })
      );
    });

    it('should handle special characters in search query', async () => {
      // Arrange
      const specialQuery = 'user-service_v2 & admin@company.com';
      mockDb.fullTextSearch.mockResolvedValue([]);

      // Act
      await searchEntities(specialQuery);

      // Assert
      expect(mockDb.fullTextSearch).toHaveBeenCalledWith('knowledge_entity',
        expect.objectContaining({
          query: specialQuery.trim(),
        })
      );
    });
  });

  describe('Integration Tests', () => {
    it('should handle complete entity lifecycle', async () => {
      // Arrange
      const entityData = {
        entity_type: 'lifecycle',
        name: 'TestEntity',
        data: { status: 'created' }
      };
      const scope = { project: 'lifecycle-test' };

      // Store
      mockDb.find.mockResolvedValue([]);
      mockDb.create.mockResolvedValue({ id: 'lifecycle-entity' });
      const storedId = await storeEntity(entityData, scope);

      // Get
      mockDb.find.mockResolvedValue([{
        id: storedId,
        entity_type: entityData.entity_type,
        name: entityData.name,
        data: entityData.data,
        scope,
        created_at: '2023-01-01T00:00:00Z',
        updated_at: '2023-01-01T00:00:00Z',
      }]);
      const retrieved = await getEntity(storedId, scope);

      // Search
      mockDb.find.mockResolvedValue([{
        id: storedId,
        entity_type: entityData.entity_type,
        name: entityData.name,
        data: entityData.data,
        scope,
        created_at: '2023-01-01T00:00:00Z',
        updated_at: '2023-01-01T00:00:00Z',
      }]);
      const searchResults = await searchEntities('TestEntity', { scope });

      // Soft Delete
      mockDb.update.mockResolvedValue({ rowCount: 1 });
      const deleted = await softDeleteEntity(storedId);

      // Assert
      expect(storedId).toBe('lifecycle-entity');
      expect(retrieved).not.toBeNull();
      expect(retrieved?.data.name).toBe('TestEntity');
      expect(searchResults).toHaveLength(1);
      expect(deleted).toBe(true);
    });
  });
});