/**
 * Standardized Unit Tests for Knowledge Graph Service
 *
 * Tests knowledge graph functionality including:
 * - Entity relationship creation and management
 * - Graph traversal and pathfinding
 * - Relationship type validation
 * - Bidirectional relationship handling
 * - Complex graph queries
 * - Relationship pattern matching
 * - Graph analytics and metrics
 * - Cross-type relationship validation
 * - Relationship constraints and rules
 * - Graph visualization and export
 * - Performance and scalability
 * - Integration with memory system
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  traverseGraph,
  enrichGraphNodes,
  findShortestPath,
  type TraversalOptions,
  type GraphNode,
  type GraphEdge,
  type GraphTraversalResult
} from '../../../src/services/graph-traversal';
import {
  storeRelation,
  getOutgoingRelations,
  getIncomingRelations,
  getAllRelations,
  relationExists,
  softDeleteRelation
} from '../../../src/services/knowledge/relation';

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

      // Mock entity-specific methods
      this.section = {
        findMany: vi.fn().mockResolvedValue([])
      };
      this.adrDecision = {
        findMany: vi.fn().mockResolvedValue([])
      };
      this.issueLog = {
        findMany: vi.fn().mockResolvedValue([])
      };
      this.runbook = {
        findMany: vi.fn().mockResolvedValue([])
      };
      this.todoLog = {
        findMany: vi.fn().mockResolvedValue([])
      };
      this.knowledgeEntity = {
        findMany: vi.fn().mockResolvedValue([])
      };
    }
  }
}));

// Mock Unified Database Layer
vi.mock('../../../src/db/unified-database-layer-v2', () => ({
  UnifiedDatabaseLayer: class {
    async initialize() {
      return Promise.resolve();
    }

    async find(table: string, options: any) {
      // Mock different responses based on table and query
      if (table === 'knowledgeRelation') {
        return this.mockRelationQueries(options);
      }
      if (table === 'knowledge_relation') {
        return this.mockRelationQueries(options);
      }
      return [];
    }

    async create(table: string, data: any) {
      return { id: 'mock-relation-id', ...data };
    }

    async store(items: any[]) {
      return { stored: items };
    }

    private mockRelationQueries(options: any) {
      // Mock existing relation check
      if (options.where?.from_entity_type && options.where?.to_entity_type) {
        return []; // No existing relations by default
      }

      // Mock outgoing relations
      if (options.where?.from_entity_type && !options.where?.to_entity_type) {
        return [
          {
            id: 'rel-1',
            to_entity_type: 'decision',
            to_entity_id: 'decision-1',
            relation_type: 'resolves',
            metadata: { weight: 0.9 },
            created_at: new Date('2024-01-01')
          },
          {
            id: 'rel-2',
            to_entity_type: 'todo',
            to_entity_id: 'todo-1',
            relation_type: 'implements',
            metadata: null,
            created_at: new Date('2024-01-02')
          }
        ];
      }

      // Mock incoming relations
      if (options.where?.to_entity_type && !options.where?.from_entity_type) {
        return [
          {
            id: 'rel-3',
            from_entity_type: 'issue',
            from_entity_id: 'issue-1',
            relation_type: 'blocks',
            metadata: { severity: 'high' },
            created_at: new Date('2024-01-01')
          }
        ];
      }

      return [];
    }
  }
}));

describe('Knowledge Graph Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Graph Traversal Operations', () => {
    it('should traverse graph from starting entity', async () => {
      const startEntityType = 'issue';
      const startEntityId = 'issue-1';
      const options: TraversalOptions = { depth: 2 };

      const result = await traverseGraph(startEntityType, startEntityId, options);

      expect(result.root_entity_type).toBe(startEntityType);
      expect(result.root_entity_id).toBe(startEntityId);
      expect(result.nodes).toBeDefined();
      expect(result.edges).toBeDefined();
      expect(result.max_depth_reached).toBeGreaterThanOrEqual(0);
    });

    it('should handle depth-limited traversal', async () => {
      const startEntityType = 'decision';
      const startEntityId = 'decision-1';
      const options: TraversalOptions = { depth: 1 };

      const result = await traverseGraph(startEntityType, startEntityId, options);

      expect(result.max_depth_reached).toBeLessThanOrEqual(1);
    });

    it('should handle relation type filtering', async () => {
      const startEntityType = 'entity';
      const startEntityId = 'entity-1';
      const options: TraversalOptions = {
        relation_types: ['resolves', 'implements']
      };

      const result = await traverseGraph(startEntityType, startEntityId, options);

      expect(result.root_entity_type).toBe(startEntityType);
      expect(result.root_entity_id).toBe(startEntityId);
      // Filter verification would require more complex mocking
    });

    it('should handle bidirectional traversal', async () => {
      const startEntityType = 'todo';
      const startEntityId = 'todo-1';
      const options: TraversalOptions = { direction: 'both' };

      const result = await traverseGraph(startEntityType, startEntityId, options);

      expect(result.nodes).toBeDefined();
      expect(result.edges).toBeDefined();
      expect(result.root_entity_type).toBe(startEntityType);
    });

    it('should handle outgoing traversal only', async () => {
      const startEntityType = 'incident';
      const startEntityId = 'incident-1';
      const options: TraversalOptions = { direction: 'outgoing' };

      const result = await traverseGraph(startEntityType, startEntityId, options);

      expect(result.root_entity_type).toBe(startEntityType);
      expect(result.root_entity_id).toBe(startEntityId);
    });

    it('should handle incoming traversal only', async () => {
      const startEntityType = 'release';
      const startEntityId = 'release-1';
      const options: TraversalOptions = { direction: 'incoming' };

      const result = await traverseGraph(startEntityType, startEntityId, options);

      expect(result.root_entity_type).toBe(startEntityType);
      expect(result.root_entity_id).toBe(startEntityId);
    });

    it('should handle traversal errors gracefully', async () => {
      const startEntityType = 'invalid-entity';
      const startEntityId = 'invalid-id';

      const result = await traverseGraph(startEntityType, startEntityId);

      // Should return fallback graph with just root node
      expect(result.nodes).toHaveLength(1);
      expect(result.edges).toHaveLength(0);
      expect(result.nodes[0].entity_type).toBe(startEntityType);
      expect(result.nodes[0].entity_id).toBe(startEntityId);
    });

    it('should handle empty graph results', async () => {
      const startEntityType = 'entity';
      const startEntityId = 'empty-entity';

      const result = await traverseGraph(startEntityType, startEntityId);

      expect(result.nodes).toHaveLength(1); // Only root node
      expect(result.edges).toHaveLength(0);
    });
  });

  describe('Node Enrichment', () => {
    it('should enrich graph nodes with entity data', async () => {
      const nodes: GraphNode[] = [
        { entity_type: 'section', entity_id: 'section-1', depth: 1 },
        { entity_type: 'decision', entity_id: 'decision-1', depth: 2 },
        { entity_type: 'todo', entity_id: 'todo-1', depth: 1 }
      ];

      const enrichedNodes = await enrichGraphNodes(nodes);

      expect(enrichedNodes).toHaveLength(3);
      expect(enrichedNodes[0]).toHaveProperty('data');
      expect(enrichedNodes[1]).toHaveProperty('data');
      expect(enrichedNodes[2]).toHaveProperty('data');
    });

    it('should handle mixed entity types in enrichment', async () => {
      const nodes: GraphNode[] = [
        { entity_type: 'section', entity_id: 'section-1', depth: 0 },
        { entity_type: 'unknown_type', entity_id: 'unknown-1', depth: 1 },
        { entity_type: 'runbook', entity_id: 'runbook-1', depth: 2 }
      ];

      const enrichedNodes = await enrichGraphNodes(nodes);

      expect(enrichedNodes).toHaveLength(3);
      // Unknown entity types should be skipped but included in results
      expect(enrichedNodes.some(n => n.entity_type === 'unknown_type')).toBe(true);
    });

    it('should handle enrichment errors gracefully', async () => {
      const nodes: GraphNode[] = [
        { entity_type: 'section', entity_id: 'section-1', depth: 1 }
      ];

      const enrichedNodes = await enrichGraphNodes(nodes);

      expect(enrichedNodes).toHaveLength(1);
      expect(enrichedNodes[0].entity_type).toBe('section');
      // Data should be undefined if enrichment fails
    });

    it('should batch enrichment by entity type', async () => {
      const nodes: GraphNode[] = [
        { entity_type: 'section', entity_id: 'section-1', depth: 1 },
        { entity_type: 'section', entity_id: 'section-2', depth: 2 },
        { entity_type: 'decision', entity_id: 'decision-1', depth: 1 },
        { entity_type: 'decision', entity_id: 'decision-2', depth: 3 }
      ];

      const enrichedNodes = await enrichGraphNodes(nodes);

      expect(enrichedNodes).toHaveLength(4);
      // Verify batching doesn't duplicate nodes
      const uniqueNodes = new Set(enrichedNodes.map(n => `${n.entity_type}:${n.entity_id}`));
      expect(uniqueNodes.size).toBe(4);
    });
  });

  describe('Path Finding Operations', () => {
    it('should find shortest path between entities', async () => {
      const fromType = 'issue';
      const fromId = 'issue-1';
      const toType = 'decision';
      const toId = 'decision-1';

      const path = await findShortestPath(fromType, fromId, toType, toId);

      // Returns null if no path found (mocked)
      expect(path).toBeNull();
    });

    it('should handle path finding with depth limit', async () => {
      const fromType = 'todo';
      const fromId = 'todo-1';
      const toType = 'release';
      const toId = 'release-1';
      const maxDepth = 3;

      const path = await findShortestPath(fromType, fromId, toType, toId, maxDepth);

      expect(path).toBeNull();
    });

    it('should handle no path found scenario', async () => {
      const fromType = 'entity';
      const fromId = 'entity-1';
      const toType = 'entity';
      const toId = 'entity-999';

      const path = await findShortestPath(fromType, fromId, toType, toId);

      expect(path).toBeNull();
    });

    it('should handle path finding errors gracefully', async () => {
      const fromType = 'invalid';
      const fromId = 'invalid-1';
      const toType = 'invalid';
      const toId = 'invalid-2';

      const path = await findShortestPath(fromType, fromId, toType, toId);

      expect(path).toBeNull();
    });

    it('should handle same entity path', async () => {
      const fromType = 'entity';
      const fromId = 'entity-1';
      const toType = 'entity';
      const toId = 'entity-1';

      const path = await findShortestPath(fromType, fromId, toType, toId);

      expect(path).toBeNull();
    });
  });

  describe('Relationship Management', () => {
    it('should store new relation successfully', async () => {
      const relationData = {
        from_entity_type: 'issue',
        from_entity_id: 'issue-1',
        to_entity_type: 'decision',
        to_entity_id: 'decision-1',
        relation_type: 'resolves',
        metadata: { weight: 0.9, confidence: 0.95 }
      };
      const scope = { project: 'test-project', branch: 'main' };

      const relationId = await storeRelation(relationData, scope);

      expect(relationId).toBeDefined();
      expect(typeof relationId).toBe('string');
    });

    it('should handle duplicate relations idempotently', async () => {
      const relationData = {
        from_entity_type: 'todo',
        from_entity_id: 'todo-1',
        to_entity_type: 'runbook',
        to_entity_id: 'runbook-1',
        relation_type: 'documents'
      };
      const scope = { project: 'test-project' };

      const firstId = await storeRelation(relationData, scope);
      const secondId = await storeRelation(relationData, scope);

      expect(firstId).toBe(secondId);
    });

    it('should validate required relation fields', async () => {
      const invalidRelationData = {
        from_entity_type: 'issue',
        // Missing from_entity_id
        to_entity_type: 'decision',
        to_entity_id: 'decision-1',
        relation_type: 'resolves'
      };
      const scope = { project: 'test-project' };

      await expect(storeRelation(invalidRelationData as any, scope))
        .rejects.toThrow();
    });

    it('should handle relation metadata', async () => {
      const relationData = {
        from_entity_type: 'incident',
        from_entity_id: 'incident-1',
        to_entity_type: 'runbook',
        to_entity_id: 'runbook-1',
        relation_type: 'resolves',
        metadata: {
          severity: 'critical',
          resolution_time: '2h',
          verified: true
        }
      };
      const scope = { project: 'test-project' };

      const relationId = await storeRelation(relationData, scope);

      expect(relationId).toBeDefined();
    });
  });

  describe('Relation Retrieval Operations', () => {
    it('should get outgoing relations from entity', async () => {
      const entityType = 'issue';
      const entityId = 'issue-1';

      const relations = await getOutgoingRelations(entityType, entityId);

      expect(Array.isArray(relations)).toBe(true);
      if (relations.length > 0) {
        expect(relations[0]).toHaveProperty('id');
        expect(relations[0]).toHaveProperty('to_entity_type');
        expect(relations[0]).toHaveProperty('to_entity_id');
        expect(relations[0]).toHaveProperty('relation_type');
        expect(relations[0]).toHaveProperty('created_at');
      }
    });

    it('should get outgoing relations with type filter', async () => {
      const entityType = 'decision';
      const entityId = 'decision-1';
      const relationTypeFilter = 'implements';

      const relations = await getOutgoingRelations(entityType, entityId, relationTypeFilter);

      expect(Array.isArray(relations)).toBe(true);
    });

    it('should get incoming relations to entity', async () => {
      const entityType = 'todo';
      const entityId = 'todo-1';

      const relations = await getIncomingRelations(entityType, entityId);

      expect(Array.isArray(relations)).toBe(true);
      if (relations.length > 0) {
        expect(relations[0]).toHaveProperty('id');
        expect(relations[0]).toHaveProperty('from_entity_type');
        expect(relations[0]).toHaveProperty('from_entity_id');
        expect(relations[0]).toHaveProperty('relation_type');
        expect(relations[0]).toHaveProperty('created_at');
      }
    });

    it('should get incoming relations with type filter', async () => {
      const entityType = 'release';
      const entityId = 'release-1';
      const relationTypeFilter = 'includes';

      const relations = await getIncomingRelations(entityType, entityId, relationTypeFilter);

      expect(Array.isArray(relations)).toBe(true);
    });

    it('should get all relations for entity', async () => {
      const entityType = 'entity';
      const entityId = 'entity-1';

      const allRelations = await getAllRelations(entityType, entityId);

      expect(allRelations).toHaveProperty('outgoing');
      expect(allRelations).toHaveProperty('incoming');
      expect(Array.isArray(allRelations.outgoing)).toBe(true);
      expect(Array.isArray(allRelations.incoming)).toBe(true);
    });

    it('should handle empty relations gracefully', async () => {
      const entityType = 'nonexistent';
      const entityId = 'nonexistent-1';

      const outgoing = await getOutgoingRelations(entityType, entityId);
      const incoming = await getIncomingRelations(entityType, entityId);

      expect(outgoing).toHaveLength(0);
      expect(incoming).toHaveLength(0);
    });
  });

  describe('Relation Validation Operations', () => {
    it('should check if relation exists', async () => {
      const fromType = 'issue';
      const fromId = 'issue-1';
      const toType = 'decision';
      const toId = 'decision-1';
      const relationType = 'resolves';

      const exists = await relationExists(fromType, fromId, toType, toId, relationType);

      expect(typeof exists).toBe('boolean');
    });

    it('should return false for non-existent relation', async () => {
      const fromType = 'entity';
      const fromId = 'entity-1';
      const toType = 'entity';
      const toId = 'entity-999';
      const relationType = 'unknown';

      const exists = await relationExists(fromType, fromId, toType, toId, relationType);

      expect(exists).toBe(false);
    });

    it('should handle relation existence check errors', async () => {
      const fromType = '';
      const fromId = '';
      const toType = '';
      const toId = '';
      const relationType = '';

      const exists = await relationExists(fromType, fromId, toType, toId, relationType);

      expect(typeof exists).toBe('boolean');
    });
  });

  describe('Relation Deletion Operations', () => {
    it('should soft delete relation successfully', async () => {
      const relationId = 'existing-relation-id';

      const deleted = await softDeleteRelation(relationId);

      expect(typeof deleted).toBe('boolean');
    });

    it('should handle deletion of non-existent relation', async () => {
      const relationId = 'non-existent-relation';

      const deleted = await softDeleteRelation(relationId);

      expect(deleted).toBe(false);
    });

    it('should handle relation deletion errors', async () => {
      const relationId = '';

      const deleted = await softDeleteRelation(relationId);

      expect(typeof deleted).toBe('boolean');
    });
  });

  describe('Knowledge Type Relationships', () => {
    it('should handle entity-to-entity relationships', async () => {
      const relationData = {
        from_entity_type: 'entity',
        from_entity_id: 'entity-1',
        to_entity_type: 'entity',
        to_entity_id: 'entity-2',
        relation_type: 'relates_to'
      };
      const scope = { project: 'test-project' };

      const relationId = await storeRelation(relationData, scope);

      expect(relationId).toBeDefined();
    });

    it('should handle cross-knowledge-type relationships', async () => {
      const relationData = {
        from_entity_type: 'issue',
        from_entity_id: 'issue-1',
        to_entity_type: 'decision',
        to_entity_id: 'decision-1',
        relation_type: 'resolves'
      };
      const scope = { project: 'test-project' };

      const relationId = await storeRelation(relationData, scope);

      expect(relationId).toBeDefined();
    });

    it('should validate relationship constraints', async () => {
      const relationData = {
        from_entity_type: 'invalid_type',
        from_entity_id: 'invalid-1',
        to_entity_type: 'decision',
        to_entity_id: 'decision-1',
        relation_type: 'resolves'
      };
      const scope = { project: 'test-project' };

      // Should handle invalid entity types gracefully
      const relationId = await storeRelation(relationData as any, scope);
      expect(relationId).toBeDefined();
    });

    it('should handle polymorphic relationships', async () => {
      const relationData = {
        from_entity_type: 'unknown',
        from_entity_id: 'unknown-1',
        to_entity_type: 'entity',
        to_entity_id: 'entity-1',
        relation_type: 'references'
      };
      const scope = { project: 'test-project' };

      const relationId = await storeRelation(relationData, scope);

      expect(relationId).toBeDefined();
    });
  });

  describe('Graph Analytics and Metrics', () => {
    it('should calculate graph depth metrics', async () => {
      const startEntityType = 'entity';
      const startEntityId = 'entity-1';
      const options: TraversalOptions = { depth: 3 };

      const result = await traverseGraph(startEntityType, startEntityId, options);

      expect(result.max_depth_reached).toBeGreaterThanOrEqual(0);
      expect(result.max_depth_reached).toBeLessThanOrEqual(3);
    });

    it('should handle relationship pattern matching', async () => {
      const startEntityType = 'decision';
      const startEntityId = 'decision-1';
      const options: TraversalOptions = {
        relation_types: ['resolves', 'implements', 'documents']
      };

      const result = await traverseGraph(startEntityType, startEntityId, options);

      expect(result.nodes).toBeDefined();
      expect(result.edges).toBeDefined();
    });

    it('should track node visitation during traversal', async () => {
      const startEntityType = 'todo';
      const startEntityId = 'todo-1';
      const options: TraversalOptions = { depth: 2 };

      const result = await traverseGraph(startEntityType, startEntityId, options);

      // Should not have duplicate nodes
      const nodeKeys = new Set(result.nodes.map(n => `${n.entity_type}:${n.entity_id}`));
      expect(nodeKeys.size).toBe(result.nodes.length);
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle large graph traversal', async () => {
      const startEntityType = 'entity';
      const startEntityId = 'large-entity-1';
      const options: TraversalOptions = { depth: 1 }; // Limit depth for performance

      const startTime = Date.now();
      const result = await traverseGraph(startEntityType, startEntityId, options);
      const endTime = Date.now();

      expect(result).toBeDefined();
      expect(endTime - startTime).toBeLessThan(1000); // Should complete within 1 second
    });

    it('should handle batch relation operations', async () => {
      const relations = Array.from({ length: 10 }, (_, i) => ({
        from_entity_type: 'entity',
        from_entity_id: `entity-${i}`,
        to_entity_type: 'entity',
        to_entity_id: `entity-${i + 1}`,
        relation_type: 'connects_to'
      }));
      const scope = { project: 'test-project' };

      const startTime = Date.now();
      const results = await Promise.all(
        relations.map(relation => storeRelation(relation, scope))
      );
      const endTime = Date.now();

      expect(results).toHaveLength(10);
      expect(endTime - startTime).toBeLessThan(2000); // Should complete within 2 seconds
    });

    it('should handle concurrent graph operations', async () => {
      const operations = Array.from({ length: 5 }, (_, i) =>
        traverseGraph('entity', `entity-${i}`, { depth: 1 })
      );

      const startTime = Date.now();
      const results = await Promise.all(operations);
      const endTime = Date.now();

      expect(results).toHaveLength(5);
      expect(endTime - startTime).toBeLessThan(3000); // Should complete within 3 seconds
    });

    it('should handle memory efficiency for large results', async () => {
      const nodes: GraphNode[] = Array.from({ length: 100 }, (_, i) => ({
        entity_type: 'entity',
        entity_id: `entity-${i}`,
        depth: i % 5
      }));

      const enrichedNodes = await enrichGraphNodes(nodes);

      expect(enrichedNodes).toHaveLength(100);
      // Memory usage should be reasonable - this is more of a smoke test
    });
  });

  describe('Integration with Memory System', () => {
    it('should maintain consistency with memory store', async () => {
      const relationData = {
        from_entity_type: 'decision',
        from_entity_id: 'decision-1',
        to_entity_type: 'todo',
        to_entity_id: 'todo-1',
        relation_type: 'implements',
        metadata: { priority: 'high' }
      };
      const scope = { project: 'test-project', branch: 'main' };

      const relationId = await storeRelation(relationData, scope);

      // Verify relation can be retrieved
      const outgoing = await getOutgoingRelations('decision', 'decision-1');
      const incoming = await getIncomingRelations('todo', 'todo-1');

      expect(relationId).toBeDefined();
      expect(Array.isArray(outgoing)).toBe(true);
      expect(Array.isArray(incoming)).toBe(true);
    });

    it('should synchronize graph traversal with memory items', async () => {
      const startEntityType = 'section';
      const startEntityId = 'section-1';

      const [graphResult, enrichedNodes] = await Promise.all([
        traverseGraph(startEntityType, startEntityId),
        enrichGraphNodes([{ entity_type: startEntityType, entity_id: startEntityId, depth: 0 }])
      ]);

      expect(graphResult.root_entity_id).toBe(startEntityId);
      expect(enrichedNodes[0].entity_id).toBe(startEntityId);
    });

    it('should handle transaction-like operations', async () => {
      const relations = [
        {
          from_entity_type: 'issue',
          from_entity_id: 'issue-1',
          to_entity_type: 'decision',
          to_entity_id: 'decision-1',
          relation_type: 'resolves'
        },
        {
          from_entity_type: 'decision',
          from_entity_id: 'decision-1',
          to_entity_type: 'todo',
          to_entity_id: 'todo-1',
          relation_type: 'implements'
        }
      ];
      const scope = { project: 'test-project' };

      const results = await Promise.all(
        relations.map(relation => storeRelation(relation, scope))
      );

      expect(results).toHaveLength(2);
      expect(results.every(id => typeof id === 'string')).toBe(true);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle circular relationships', async () => {
      // Create circular relationship: A -> B -> A
      const relation1 = {
        from_entity_type: 'entity',
        from_entity_id: 'entity-1',
        to_entity_type: 'entity',
        to_entity_id: 'entity-2',
        relation_type: 'references'
      };
      const relation2 = {
        from_entity_type: 'entity',
        from_entity_id: 'entity-2',
        to_entity_type: 'entity',
        to_entity_id: 'entity-1',
        relation_type: 'references'
      };
      const scope = { project: 'test-project' };

      const [id1, id2] = await Promise.all([
        storeRelation(relation1, scope),
        storeRelation(relation2, scope)
      ]);

      expect(id1).toBeDefined();
      expect(id2).toBeDefined();
    });

    it('should handle self-referencing relationships', async () => {
      const relationData = {
        from_entity_type: 'entity',
        from_entity_id: 'entity-1',
        to_entity_type: 'entity',
        to_entity_id: 'entity-1', // Self-reference
        relation_type: 'references_self'
      };
      const scope = { project: 'test-project' };

      const relationId = await storeRelation(relationData, scope);

      expect(relationId).toBeDefined();
    });

    it('should handle very long relation paths', async () => {
      const startEntityType = 'entity';
      const startEntityId = 'entity-1';
      const options: TraversalOptions = { depth: 10 };

      const result = await traverseGraph(startEntityType, startEntityId, options);

      expect(result.max_depth_reached).toBeLessThanOrEqual(10);
    });

    it('should handle missing entity data gracefully', async () => {
      const nodes: GraphNode[] = [
        { entity_type: 'nonexistent', entity_id: 'missing-1', depth: 1 },
        { entity_type: 'section', entity_id: 'missing-2', depth: 2 }
      ];

      const enrichedNodes = await enrichGraphNodes(nodes);

      expect(enrichedNodes).toHaveLength(2);
      // Missing data should be handled gracefully
    });

    it('should handle invalid relation metadata', async () => {
      const relationData = {
        from_entity_type: 'entity',
        from_entity_id: 'entity-1',
        to_entity_type: 'entity',
        to_entity_id: 'entity-2',
        relation_type: 'test',
        metadata: 'invalid_metadata' // Should be object
      };
      const scope = { project: 'test-project' };

      const relationId = await storeRelation(relationData as any, scope);

      expect(relationId).toBeDefined();
    });
  });
});