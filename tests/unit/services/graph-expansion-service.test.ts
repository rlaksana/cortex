/**
 * Graph Expansion Service Tests
 * P4-T4.2: Test-driven development for graph expansion functionality
 *
 * Test Coverage:
 * - Basic expansion functionality (relations, parents, children)
 * - Performance limits (≤20 neighbors)
 * - Match type tagging ('graph')
 * - Integration with relation storage
 * - Scope filtering
 * - Error handling and edge cases
 * - Configuration management
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { GraphExpansionService } from '../../../src/services/search/graph-expansion-service';
import type { SearchResult, SearchQuery } from '../../../src/types/core-interfaces';

// Mock the relation service
vi.mock('../../../src/services/knowledge/relation', () => ({
  getOutgoingRelations: vi.fn(),
  getIncomingRelations: vi.fn(),
}));

// Mock the database layer
vi.mock('../../../src/db/unified-database-layer-v2', () => ({
  UnifiedDatabaseLayer: vi.fn().mockImplementation(() => ({
    initialize: vi.fn().mockResolvedValue(undefined),
    find: vi.fn(),
    create: vi.fn(),
    store: vi.fn(),
  })),
}));

describe('GraphExpansionService', () => {
  let service: GraphExpansionService;
  let mockGetOutgoingRelations: any;
  let mockGetIncomingRelations: any;
  let mockUnifiedDatabaseLayer: any;

  beforeEach(async () => {
    // Reset mocks
    vi.clearAllMocks();

    // Get mock functions
    const { getOutgoingRelations, getIncomingRelations } = await import('../../../src/services/knowledge/relation');
    mockGetOutgoingRelations = getOutgoingRelations;
    mockGetIncomingRelations = getIncomingRelations;

    const { UnifiedDatabaseLayer } = await import('../../../src/db/unified-database-layer-v2');
    mockUnifiedDatabaseLayer = UnifiedDatabaseLayer;

    // Create service instance
    service = new GraphExpansionService();
  });

  describe('Basic Functionality', () => {
    it('should return initial results unchanged when expand=none', async () => {
      // Arrange
      const initialResults: SearchResult[] = [
        {
          id: 'test-id-1',
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Decision' },
          created_at: '2024-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'semantic'
        }
      ];

      const query: SearchQuery = {
        query: 'test query',
        expand: 'none'
      };

      // Act
      const result = await service.expandResults(initialResults, query);

      // Assert
      expect(result.expandedResults).toEqual(initialResults);
      expect(result.expansionMetadata.totalExpansions).toBe(0);
      expect(result.expansionMetadata.expansionType).toBe('none');
      expect(result.expansionMetadata.neighborsFound).toBe(0);
      expect(result.expansionMetadata.neighborsLimited).toBe(false);
    });

    it('should expand with relations mode (both parents and children)', async () => {
      // Arrange
      const initialResults: SearchResult[] = [
        {
          id: 'test-id-1',
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Decision' },
          created_at: '2024-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'semantic'
        }
      ];

      // Mock outgoing relations
      mockGetOutgoingRelations.mockResolvedValue([
        {
          id: 'relation-1',
          to_entity_type: 'issue',
          to_entity_id: 'issue-id-1',
          relation_type: 'resolves',
          metadata: null,
          created_at: new Date()
        }
      ]);

      // Mock incoming relations
      mockGetIncomingRelations.mockResolvedValue([
        {
          id: 'relation-2',
          from_entity_type: 'todo',
          from_entity_id: 'todo-id-1',
          relation_type: 'implements',
          metadata: null,
          created_at: new Date()
        }
      ]);

      // Mock database responses for related entities
      const mockDb = {
        initialize: vi.fn().mockResolvedValue(undefined),
        find: vi.fn().mockImplementation((table, query) => {
          if (query.id === 'issue-id-1') {
            return Promise.resolve([{
              id: 'issue-id-1',
              data: { title: 'Related Issue', description: 'Issue description' },
              tags: { project: 'test', branch: 'main' },
              created_at: new Date('2024-01-02T00:00:00Z')
            }]);
          }
          if (query.id === 'todo-id-1') {
            return Promise.resolve([{
              id: 'todo-id-1',
              data: { title: 'Related Todo', description: 'Todo description' },
              tags: { project: 'test', branch: 'main' },
              created_at: new Date('2024-01-03T00:00:00Z')
            }]);
          }
          return Promise.resolve([]);
        })
      };
      mockUnifiedDatabaseLayer.mockImplementation(() => mockDb);

      const query: SearchQuery = {
        query: 'test query',
        expand: 'relations'
      };

      // Act
      const result = await service.expandResults(initialResults, query);

      // Assert
      expect(result.expandedResults).toHaveLength(3); // 1 initial + 2 expanded
      expect(result.expansionMetadata.totalExpansions).toBe(2);
      expect(result.expansionMetadata.expansionType).toBe('relations');
      expect(result.expansionMetadata.neighborsFound).toBe(2);
      expect(result.expansionMetadata.neighborsLimited).toBe(false);

      // Check that expanded results have correct match_type and reduced confidence
      const expandedResults = result.expandedResults.filter(r => r.match_type === 'graph');
      expect(expandedResults).toHaveLength(2);
      expandedResults.forEach(result => {
        expect(result.confidence_score).toBeLessThan(0.9); // Should be reduced
        expect(result.match_type).toBe('graph');
      });
    });

    it('should expand with parents mode (incoming relations only)', async () => {
      // Arrange
      const initialResults: SearchResult[] = [
        {
          id: 'test-id-1',
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Decision' },
          created_at: '2024-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'semantic'
        }
      ];

      // Mock only incoming relations
      mockGetIncomingRelations.mockResolvedValue([
        {
          id: 'relation-1',
          from_entity_type: 'todo',
          from_entity_id: 'todo-id-1',
          relation_type: 'implements',
          metadata: null,
          created_at: new Date()
        }
      ]);

      mockGetOutgoingRelations.mockResolvedValue([]); // No outgoing relations

      // Mock database response
      const mockDb = {
        initialize: vi.fn().mockResolvedValue(undefined),
        find: vi.fn().mockResolvedValue([{
          id: 'todo-id-1',
          data: { title: 'Parent Todo' },
          tags: { project: 'test', branch: 'main' },
          created_at: new Date('2024-01-02T00:00:00Z')
        }])
      };
      mockUnifiedDatabaseLayer.mockImplementation(() => mockDb);

      const query: SearchQuery = {
        query: 'test query',
        expand: 'parents'
      };

      // Act
      const result = await service.expandResults(initialResults, query);

      // Assert
      expect(result.expandedResults).toHaveLength(2); // 1 initial + 1 expanded
      expect(result.expansionMetadata.expansionType).toBe('parents');
      expect(result.expansionMetadata.neighborsFound).toBe(1);

      // Should only call getIncomingRelations, not getOutgoingRelations
      expect(mockGetIncomingRelations).toHaveBeenCalledWith('decision', 'test-id-1', undefined);
      expect(mockGetOutgoingRelations).not.toHaveBeenCalled();
    });

    it('should expand with children mode (outgoing relations only)', async () => {
      // Arrange
      const initialResults: SearchResult[] = [
        {
          id: 'test-id-1',
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Decision' },
          created_at: '2024-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'semantic'
        }
      ];

      // Mock only outgoing relations
      mockGetOutgoingRelations.mockResolvedValue([
        {
          id: 'relation-1',
          to_entity_type: 'issue',
          to_entity_id: 'issue-id-1',
          relation_type: 'resolves',
          metadata: null,
          created_at: new Date()
        }
      ]);

      mockGetIncomingRelations.mockResolvedValue([]); // No incoming relations

      // Mock database response
      const mockDb = {
        initialize: vi.fn().mockResolvedValue(undefined),
        find: vi.fn().mockResolvedValue([{
          id: 'issue-id-1',
          data: { title: 'Child Issue' },
          tags: { project: 'test', branch: 'main' },
          created_at: new Date('2024-01-02T00:00:00Z')
        }])
      };
      mockUnifiedDatabaseLayer.mockImplementation(() => mockDb);

      const query: SearchQuery = {
        query: 'test query',
        expand: 'children'
      };

      // Act
      const result = await service.expandResults(initialResults, query);

      // Assert
      expect(result.expandedResults).toHaveLength(2); // 1 initial + 1 expanded
      expect(result.expansionMetadata.expansionType).toBe('children');
      expect(result.expansionMetadata.neighborsFound).toBe(1);

      // Should only call getOutgoingRelations, not getIncomingRelations
      expect(mockGetOutgoingRelations).toHaveBeenCalledWith('decision', 'test-id-1', undefined);
      expect(mockGetIncomingRelations).not.toHaveBeenCalled();
    });
  });

  describe('Performance Limits', () => {
    it('should limit expansion to 20 neighbors maximum', async () => {
      // Arrange
      const initialResults: SearchResult[] = [
        {
          id: 'test-id-1',
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Decision' },
          created_at: '2024-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'semantic'
        }
      ];

      // Mock 25 outgoing relations (exceeding the 20 limit)
      const outgoingRelations = Array.from({ length: 25 }, (_, i) => ({
        id: `relation-${i}`,
        to_entity_type: 'issue',
        to_entity_id: `issue-id-${i}`,
        relation_type: 'resolves',
        metadata: null,
        created_at: new Date()
      }));

      mockGetOutgoingRelations.mockResolvedValue(outgoingRelations);
      mockGetIncomingRelations.mockResolvedValue([]);

      // Mock database responses for many entities
      const mockDb = {
        initialize: vi.fn().mockResolvedValue(undefined),
        find: vi.fn().mockResolvedValue([{
          id: 'issue-id',
          data: { title: 'Related Issue' },
          tags: { project: 'test', branch: 'main' },
          created_at: new Date('2024-01-02T00:00:00Z')
        }])
      };
      mockUnifiedDatabaseLayer.mockImplementation(() => mockDb);

      const query: SearchQuery = {
        query: 'test query',
        expand: 'children'
      };

      // Act
      const result = await service.expandResults(initialResults, query);

      // Assert
      expect(result.expansionMetadata.neighborsLimited).toBe(true);
      expect(result.expansionMetadata.neighborsFound).toBeLessThanOrEqual(20);
      expect(result.expansionMetadata.totalExpansions).toBeLessThanOrEqual(20);
    });

    it('should respect custom maxNeighbors configuration', async () => {
      // Arrange
      const customService = new GraphExpansionService({ maxNeighbors: 5 });

      const initialResults: SearchResult[] = [
        {
          id: 'test-id-1',
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Decision' },
          created_at: '2024-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'semantic'
        }
      ];

      // Mock 10 relations (exceeding custom limit of 5)
      const outgoingRelations = Array.from({ length: 10 }, (_, i) => ({
        id: `relation-${i}`,
        to_entity_type: 'issue',
        to_entity_id: `issue-id-${i}`,
        relation_type: 'resolves',
        metadata: null,
        created_at: new Date()
      }));

      mockGetOutgoingRelations.mockResolvedValue(outgoingRelations);
      mockGetIncomingRelations.mockResolvedValue([]);

      const mockDb = {
        initialize: vi.fn().mockResolvedValue(undefined),
        find: vi.fn().mockResolvedValue([{
          id: 'issue-id',
          data: { title: 'Related Issue' },
          tags: { project: 'test', branch: 'main' },
          created_at: new Date('2024-01-02T00:00:00Z')
        }])
      };
      mockUnifiedDatabaseLayer.mockImplementation(() => mockDb);

      const query: SearchQuery = {
        query: 'test query',
        expand: 'children'
      };

      // Act
      const result = await customService.expandResults(initialResults, query);

      // Assert
      expect(result.expansionMetadata.neighborsLimited).toBe(true);
      expect(result.expansionMetadata.neighborsFound).toBeLessThanOrEqual(5);
    });
  });

  describe('Match Type Tagging', () => {
    it('should tag expanded results with match_type=graph', async () => {
      // Arrange
      const initialResults: SearchResult[] = [
        {
          id: 'test-id-1',
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Decision' },
          created_at: '2024-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'semantic'
        }
      ];

      mockGetOutgoingRelations.mockResolvedValue([
        {
          id: 'relation-1',
          to_entity_type: 'issue',
          to_entity_id: 'issue-id-1',
          relation_type: 'resolves',
          metadata: null,
          created_at: new Date()
        }
      ]);

      mockGetIncomingRelations.mockResolvedValue([]);

      const mockDb = {
        initialize: vi.fn().mockResolvedValue(undefined),
        find: vi.fn().mockResolvedValue([{
          id: 'issue-id-1',
          data: { title: 'Related Issue' },
          tags: { project: 'test', branch: 'main' },
          created_at: new Date('2024-01-02T00:00:00Z')
        }])
      };
      mockUnifiedDatabaseLayer.mockImplementation(() => mockDb);

      const query: SearchQuery = {
        query: 'test query',
        expand: 'children'
      };

      // Act
      const result = await service.expandResults(initialResults, query);

      // Assert
      const originalResults = result.expandedResults.filter(r => r.match_type !== 'graph');
      const expandedResults = result.expandedResults.filter(r => r.match_type === 'graph');

      expect(originalResults).toHaveLength(1);
      expect(originalResults[0].match_type).toBe('semantic'); // Original match type preserved
      expect(expandedResults).toHaveLength(1);
      expect(expandedResults[0].match_type).toBe('graph'); // Expanded result tagged as graph
    });

    it('should apply confidence reduction to expanded results', async () => {
      // Arrange
      const customService = new GraphExpansionService({ confidenceReduction: 0.5 });

      const initialResults: SearchResult[] = [
        {
          id: 'test-id-1',
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Decision' },
          created_at: '2024-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'semantic'
        }
      ];

      mockGetOutgoingRelations.mockResolvedValue([
        {
          id: 'relation-1',
          to_entity_type: 'issue',
          to_entity_id: 'issue-id-1',
          relation_type: 'resolves',
          metadata: null,
          created_at: new Date()
        }
      ]);

      mockGetIncomingRelations.mockResolvedValue([]);

      const mockDb = {
        initialize: vi.fn().mockResolvedValue(undefined),
        find: vi.fn().mockResolvedValue([{
          id: 'issue-id-1',
          data: { title: 'Related Issue' },
          tags: { project: 'test', branch: 'main' },
          created_at: new Date('2024-01-02T00:00:00Z')
        }])
      };
      mockUnifiedDatabaseLayer.mockImplementation(() => mockDb);

      const query: SearchQuery = {
        query: 'test query',
        expand: 'children'
      };

      // Act
      const result = await customService.expandResults(initialResults, query);

      // Assert
      const expandedResults = result.expandedResults.filter(r => r.match_type === 'graph');
      expect(expandedResults).toHaveLength(1);
      expect(expandedResults[0].confidence_score).toBe(0.35); // 0.7 * 0.5
    });
  });

  describe('Scope Filtering', () => {
    it('should filter expanded results by query scope', async () => {
      // Arrange
      const initialResults: SearchResult[] = [
        {
          id: 'test-id-1',
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Decision' },
          created_at: '2024-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'semantic'
        }
      ];

      mockGetOutgoingRelations.mockResolvedValue([
        {
          id: 'relation-1',
          to_entity_type: 'issue',
          to_entity_id: 'issue-id-1', // Same scope
          relation_type: 'resolves',
          metadata: null,
          created_at: new Date()
        },
        {
          id: 'relation-2',
          to_entity_type: 'issue',
          to_entity_id: 'issue-id-2', // Different scope
          relation_type: 'relates_to',
          metadata: null,
          created_at: new Date()
        }
      ]);

      mockGetIncomingRelations.mockResolvedValue([]);

      // Mock database responses with different scopes
      const mockDb = {
        initialize: vi.fn().mockResolvedValue(undefined),
        find: vi.fn().mockImplementation((table, query) => {
          if (query.id === 'issue-id-1') {
            return Promise.resolve([{
              id: 'issue-id-1',
              data: { title: 'Same Scope Issue' },
              tags: { project: 'test', branch: 'main' }, // Same scope
              created_at: new Date('2024-01-02T00:00:00Z')
            }]);
          }
          if (query.id === 'issue-id-2') {
            return Promise.resolve([{
              id: 'issue-id-2',
              data: { title: 'Different Scope Issue' },
              tags: { project: 'other', branch: 'dev' }, // Different scope
              created_at: new Date('2024-01-03T00:00:00Z')
            }]);
          }
          return Promise.resolve([]);
        })
      };
      mockUnifiedDatabaseLayer.mockImplementation(() => mockDb);

      const query: SearchQuery = {
        query: 'test query',
        expand: 'children',
        scope: { project: 'test', branch: 'main' } // Filter for specific scope
      };

      // Act
      const result = await service.expandResults(initialResults, query);

      // Assert
      expect(result.expansionMetadata.neighborsFound).toBe(1); // Only 1 matches scope
      expect(result.expansionMetadata.totalExpansions).toBe(1);

      const expandedResults = result.expandedResults.filter(r => r.match_type === 'graph');
      expect(expandedResults).toHaveLength(1);
      expect(expandedResults[0].id).toBe('issue-id-1'); // Only the matching scope entity
    });
  });

  describe('Error Handling', () => {
    it('should handle relation service errors gracefully', async () => {
      // Arrange
      const initialResults: SearchResult[] = [
        {
          id: 'test-id-1',
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Decision' },
          created_at: '2024-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'semantic'
        }
      ];

      // Mock relation service to throw error
      mockGetOutgoingRelations.mockRejectedValue(new Error('Relation service error'));
      mockGetIncomingRelations.mockRejectedValue(new Error('Relation service error'));

      const query: SearchQuery = {
        query: 'test query',
        expand: 'relations'
      };

      // Act
      const result = await service.expandResults(initialResults, query);

      // Assert
      expect(result.expandedResults).toEqual(initialResults); // Return initial results
      expect(result.expansionMetadata.totalExpansions).toBe(0);
      expect(result.expansionMetadata.neighborsFound).toBe(0);
    });

    it('should handle database errors gracefully', async () => {
      // Arrange
      const initialResults: SearchResult[] = [
        {
          id: 'test-id-1',
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Decision' },
          created_at: '2024-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'semantic'
        }
      ];

      mockGetOutgoingRelations.mockResolvedValue([
        {
          id: 'relation-1',
          to_entity_type: 'issue',
          to_entity_id: 'issue-id-1',
          relation_type: 'resolves',
          metadata: null,
          created_at: new Date()
        }
      ]);

      mockGetIncomingRelations.mockResolvedValue([]);

      // Mock database to throw error
      const mockDb = {
        initialize: vi.fn().mockRejectedValue(new Error('Database error')),
        find: vi.fn()
      };
      mockUnifiedDatabaseLayer.mockImplementation(() => mockDb);

      const query: SearchQuery = {
        query: 'test query',
        expand: 'children'
      };

      // Act
      const result = await service.expandResults(initialResults, query);

      // Assert
      expect(result.expandedResults).toEqual(initialResults); // Return initial results
      expect(result.expansionMetadata.totalExpansions).toBe(0);
    });

    it('should handle unknown entity types gracefully', async () => {
      // Arrange
      const initialResults: SearchResult[] = [
        {
          id: 'test-id-1',
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Decision' },
          created_at: '2024-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'semantic'
        }
      ];

      mockGetOutgoingRelations.mockResolvedValue([
        {
          id: 'relation-1',
          to_entity_type: 'unknown_type', // Unknown entity type
          to_entity_id: 'unknown-id-1',
          relation_type: 'resolves',
          metadata: null,
          created_at: new Date()
        }
      ]);

      mockGetIncomingRelations.mockResolvedValue([]);

      const query: SearchQuery = {
        query: 'test query',
        expand: 'children'
      };

      // Act
      const result = await service.expandResults(initialResults, query);

      // Assert
      expect(result.expansionMetadata.totalExpansions).toBe(0); // No expansions due to unknown type
      expect(result.expandedResults).toEqual(initialResults);
    });
  });

  describe('Configuration Management', () => {
    it('should allow updating configuration', () => {
      // Act
      service.updateConfig({
        maxNeighbors: 15,
        confidenceReduction: 0.7
      });

      const config = service.getConfig();

      // Assert
      expect(config.maxNeighbors).toBe(15);
      expect(config.confidenceReduction).toBe(0.7);
    });

    it('should merge partial configuration updates', () => {
      // Arrange
      const originalConfig = service.getConfig();

      // Act
      service.updateConfig({ maxNeighbors: 5 });
      const updatedConfig = service.getConfig();

      // Assert
      expect(updatedConfig.maxNeighbors).toBe(5); // Updated
      expect(updatedConfig.confidenceReduction).toBe(originalConfig.confidenceReduction); // Preserved
    });
  });

  describe('Deduplication', () => {
    it('should remove duplicate expanded results', async () => {
      // Arrange
      const initialResults: SearchResult[] = [
        {
          id: 'test-id-1',
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Decision' },
          created_at: '2024-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'semantic'
        }
      ];

      // Mock relations that point to the same entity (creating duplicates)
      mockGetOutgoingRelations.mockResolvedValue([
        {
          id: 'relation-1',
          to_entity_type: 'issue',
          to_entity_id: 'duplicate-id', // Same target entity
          relation_type: 'resolves',
          metadata: null,
          created_at: new Date()
        }
      ]);

      mockGetIncomingRelations.mockResolvedValue([
        {
          id: 'relation-2',
          from_entity_type: 'todo',
          from_entity_id: 'duplicate-id', // Same target entity
          relation_type: 'implements',
          metadata: null,
          created_at: new Date()
        }
      ]);

      const mockDb = {
        initialize: vi.fn().mockResolvedValue(undefined),
        find: vi.fn().mockResolvedValue([{
          id: 'duplicate-id',
          data: { title: 'Duplicate Entity' },
          tags: { project: 'test', branch: 'main' },
          created_at: new Date('2024-01-02T00:00:00Z')
        }])
      };
      mockUnifiedDatabaseLayer.mockImplementation(() => mockDb);

      const query: SearchQuery = {
        query: 'test query',
        expand: 'relations'
      };

      // Act
      const result = await service.expandResults(initialResults, query);

      // Assert
      expect(result.expandedResults).toHaveLength(2); // 1 initial + 1 unique expanded (not 3)
      expect(result.expansionMetadata.totalExpansions).toBe(1); // Only 1 unique expansion
    });
  });
});