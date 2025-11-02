/**
 * Comprehensive Unit Tests for Relation Knowledge Type
 *
 * Tests relation knowledge type functionality including:
 * - Entity relationship validation
 * - UUID reference validation
 * - Relation type constraints
 * - Graph relationship integrity
 * - Scope isolation for relationships
 * - Error handling and edge cases
 * - Integration with entity relationships
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { VectorDatabase } from '../../../src/index';
import { RelationSchema, validateKnowledgeItem } from '../../../src/schemas/knowledge-types';

// Mock Qdrant client - reusing pattern from memory-store.test.ts
vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class {
    constructor() {
      this.getCollections = vi.fn().mockResolvedValue({
        collections: [{ name: 'test-collection' }],
      });
      this.createCollection = vi.fn().mockResolvedValue(undefined);
      this.upsert = vi.fn().mockResolvedValue(undefined);
      this.search = vi.fn().mockResolvedValue([]);
      this.getCollection = vi.fn().mockResolvedValue({
        points_count: 0,
        status: 'green',
      });
      this.delete = vi.fn().mockResolvedValue({ status: 'completed' });
      this.count = vi.fn().mockResolvedValue({ count: 0 });
      this.healthCheck = vi.fn().mockResolvedValue(true);
    }
  },
}));

describe('Relation Knowledge Type - Comprehensive Testing', () => {
  let db: VectorDatabase;
  let mockQdrant: any;

  beforeEach(() => {
    db = new VectorDatabase();
    mockQdrant = (db as any).client;
  });

  describe('Relation Schema Validation', () => {
    it('should validate complete relation with all fields', () => {
      const relation = {
        kind: 'relation' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          from_entity_type: 'decision',
          from_entity_id: '550e8400-e29b-41d4-a716-446655440000',
          to_entity_type: 'entity',
          to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
          relationType: 'resolves',
          metadata: {
            weight: 1.0,
            confidence: 0.85,
            since: '2025-01-01',
          },
        },
        tags: { graph_relation: true, verified: true },
        source: {
          actor: 'system-architect',
          tool: 'graph-builder',
          timestamp: '2025-01-01T00:00:00Z',
        },
      };

      const result = RelationSchema.safeParse(relation);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.kind).toBe('relation');
        expect(result.data.data.from_entity_type).toBe('decision');
        expect(result.data.data.to_entity_type).toBe('entity');
        expect(result.data.data.relationType).toBe('resolves');
        expect(result.data.data.metadata.weight).toBe(1.0);
      }
    });

    it('should validate minimal relation with only required fields', () => {
      const relation = {
        kind: 'relation' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          from_entity_type: 'issue',
          from_entity_id: '550e8400-e29b-41d4-a716-446655440000',
          to_entity_type: 'decision',
          to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
          relationType: 'addresses',
        },
      };

      const result = RelationSchema.safeParse(relation);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.from_entity_type).toBe('issue');
        expect(result.data.data.to_entity_type).toBe('decision');
        expect(result.data.data.relationType).toBe('addresses');
        expect(result.data.data.metadata).toBeUndefined();
      }
    });

    it('should reject relation missing required fields', () => {
      const invalidRelations = [
        {
          kind: 'relation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            // Missing from_entity_type
            from_entity_id: '550e8400-e29b-41d4-a716-446655440000',
            to_entity_type: 'entity',
            to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
            relationType: 'connects',
          },
        },
        {
          kind: 'relation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            from_entity_type: 'entity',
            // Missing from_entity_id
            to_entity_type: 'entity',
            to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
            relationType: 'connects',
          },
        },
        {
          kind: 'relation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            from_entity_type: 'entity',
            from_entity_id: '550e8400-e29b-41d4-a716-446655440000',
            // Missing to_entity_type
            to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
            relationType: 'connects',
          },
        },
        {
          kind: 'relation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            from_entity_type: 'entity',
            from_entity_id: '550e8400-e29b-41d4-a716-446655440000',
            to_entity_type: 'entity',
            to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
            // Missing relationType
          },
        },
      ];

      invalidRelations.forEach((relation, index) => {
        const result = RelationSchema.safeParse(relation);
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues.length).toBeGreaterThan(0);
        }
      });
    });

    it('should reject relation with invalid UUID formats', () => {
      const invalidRelations = [
        {
          kind: 'relation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            from_entity_type: 'entity',
            from_entity_id: 'invalid-uuid-format', // Invalid UUID
            to_entity_type: 'entity',
            to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
            relationType: 'connects',
          },
        },
        {
          kind: 'relation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            from_entity_type: 'entity',
            from_entity_id: '550e8400-e29b-41d4-a716-446655440000',
            to_entity_type: 'entity',
            to_entity_id: 'not-a-uuid', // Invalid UUID
            relationType: 'connects',
          },
        },
      ];

      invalidRelations.forEach((relation) => {
        const result = RelationSchema.safeParse(relation);
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues[0].message).toContain('UUID');
        }
      });
    });

    it('should enforce entity_type length constraints', () => {
      const relation = {
        kind: 'relation' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          from_entity_type: 'x'.repeat(101), // Exceeds 100 character limit
          from_entity_id: '550e8400-e29b-41d4-a716-446655440000',
          to_entity_type: 'entity',
          to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
          relationType: 'connects',
        },
      };

      const result = RelationSchema.safeParse(relation);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('100 characters or less');
      }
    });

    it('should enforce relationType length constraints', () => {
      const relation = {
        kind: 'relation' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          from_entity_type: 'entity',
          from_entity_id: '550e8400-e29b-41d4-a716-446655440000',
          to_entity_type: 'entity',
          to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
          relationType: 'x'.repeat(101), // Exceeds 100 character limit
        },
      };

      const result = RelationSchema.safeParse(relation);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('100 characters or less');
      }
    });
  });

  describe('Relation Storage Operations', () => {
    it('should store relation successfully using memory_store pattern', async () => {
      const relation = {
        kind: 'relation' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          from_entity_type: 'issue',
          from_entity_id: '550e8400-e29b-41d4-a716-446655440000',
          to_entity_type: 'decision',
          to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
          relationType: 'resolves',
        },
        content: 'Relation: issue resolves decision', // Required for embedding generation
      };

      const result = await db.storeItems([relation]);

      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      expect(result.stored[0]).toHaveProperty('id');
      expect(result.stored[0].kind).toBe('relation');
      expect(result.stored[0].data.relationType).toBe('resolves');
      expect(result.stored[0].data.from_entity_type).toBe('issue');

      // Verify Qdrant client was called
      expect(mockQdrant.upsert).toHaveBeenCalled();
    });

    it('should handle batch relation storage successfully', async () => {
      const relations = Array.from({ length: 3 }, (_, i) => ({
        kind: 'relation' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          from_entity_type: 'entity',
          from_entity_id: `550e8400-e29b-41d4-a716-44665544${String(i).padStart(3, '0')}0`,
          to_entity_type: 'entity',
          to_entity_id: `550e8400-e29b-41d4-a716-44665544${String(i).padStart(3, '0')}1`,
          relationType: `relationType_${i}`,
        },
        content: `Relation: entity ${i} connects to entity ${i + 1}`,
      }));

      const result = await db.storeItems(relations);

      expect(result.stored).toHaveLength(3);
      expect(result.errors).toHaveLength(0);
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(3);
    });

    it('should handle mixed valid and invalid relations in batch', async () => {
      const items = [
        {
          kind: 'relation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            from_entity_type: 'decision',
            from_entity_id: '550e8400-e29b-41d4-a716-446655440000',
            to_entity_type: 'entity',
            to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
            relationType: 'implements',
          },
          content: 'Valid relation',
        },
        {
          kind: 'relation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            from_entity_type: 'entity',
            // Missing from_entity_id
            to_entity_type: 'entity',
            to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
            relationType: 'connects',
          },
          content: 'Invalid relation missing ID',
        },
        {
          kind: 'relation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            from_entity_type: 'todo',
            from_entity_id: '550e8400-e29b-41d4-a716-446655440002',
            to_entity_type: 'release',
            to_entity_id: '550e8400-e29b-41d4-a716-446655440003',
            relationType: 'included_in',
          },
          content: 'Another valid relation',
        },
      ];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(2); // 2 valid relations
      expect(result.errors).toHaveLength(1); // 1 invalid relation
    });
  });

  describe('Relation Search Operations', () => {
    beforeEach(() => {
      // Setup search mock for relations
      mockQdrant.search.mockResolvedValue([
        {
          id: 'relation-id-1',
          score: 0.9,
          payload: {
            kind: 'relation',
            data: {
              from_entity_type: 'decision',
              from_entity_id: '550e8400-e29b-41d4-a716-446655440000',
              to_entity_type: 'entity',
              to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
              relationType: 'implements',
            },
            scope: { project: 'test-project', branch: 'main' },
          },
        },
        {
          id: 'relation-id-2',
          score: 0.8,
          payload: {
            kind: 'relation',
            data: {
              from_entity_type: 'issue',
              from_entity_id: '550e8400-e29b-41d4-a716-446655440002',
              to_entity_type: 'decision',
              to_entity_id: '550e8400-e29b-41d4-a716-446655440003',
              relationType: 'resolves',
            },
            scope: { project: 'test-project', branch: 'main' },
          },
        },
      ]);
    });

    it('should find relations by query', async () => {
      const query = 'decision implements entity';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[0].data.relationType).toBe('implements');
      expect(result.items[0].data.from_entity_type).toBe('decision');
      expect(result.items[1].data.relationType).toBe('resolves');
      expect(mockQdrant.search).toHaveBeenCalled();
    });

    it('should handle empty relation search results', async () => {
      mockQdrant.search.mockResolvedValue([]);

      const result = await db.searchItems('nonexistent relation');

      expect(result.items).toHaveLength(0);
      expect(result.total).toBe(0);
    });
  });

  describe('Graph Relationship Types', () => {
    it('should handle common graph relationship types', async () => {
      const relationTypes = [
        'resolves',
        'implements',
        'references',
        'supersedes',
        'depends_on',
        'relates_to',
        'connects',
        'includes',
      ];

      for (const relationType of relationTypes) {
        const relation = {
          kind: 'relation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            from_entity_type: 'entity',
            from_entity_id: '550e8400-e29b-41d4-a716-446655440000',
            to_entity_type: 'entity',
            to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
            relationType,
          },
          content: `Relation: entity ${relationType} entity`,
        };

        const result = RelationSchema.safeParse(relation);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.data.relationType).toBe(relationType);
        }
      }
    });

    it('should validate bidirectional relationships', async () => {
      const relationA = {
        kind: 'relation' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          from_entity_type: 'decision',
          from_entity_id: '550e8400-e29b-41d4-a716-446655440000',
          to_entity_type: 'runbook',
          to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
          relationType: 'requires',
        },
        content: 'Decision requires runbook',
      };

      const relationB = {
        kind: 'relation' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          from_entity_type: 'runbook',
          from_entity_id: '550e8400-e29b-41d4-a716-446655440001',
          to_entity_type: 'decision',
          to_entity_id: '550e8400-e29b-41d4-a716-446655440000',
          relationType: 'supports',
        },
        content: 'Runbook supports decision',
      };

      const resultA = RelationSchema.safeParse(relationA);
      const resultB = RelationSchema.safeParse(relationB);

      expect(resultA.success).toBe(true);
      expect(resultB.success).toBe(true);
    });
  });

  describe('Relation Scope Isolation', () => {
    it('should isolate relations by project scope', async () => {
      const relationProjectA = {
        kind: 'relation' as const,
        scope: {
          project: 'project-A',
          branch: 'main',
        },
        data: {
          from_entity_type: 'entity',
          from_entity_id: '550e8400-e29b-41d4-a716-446655440000',
          to_entity_type: 'entity',
          to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
          relationType: 'connects',
        },
        content: 'Relation in project-A',
      };

      const relationProjectB = {
        kind: 'relation' as const,
        scope: {
          project: 'project-B',
          branch: 'main',
        },
        data: {
          from_entity_type: 'entity',
          from_entity_id: '550e8400-e29b-41d4-a716-446655440002',
          to_entity_type: 'entity',
          to_entity_id: '550e8400-e29b-41d4-a716-446655440003',
          relationType: 'connects',
        },
        content: 'Relation in project-B',
      };

      // Store both relations
      await db.storeItems([relationProjectA, relationProjectB]);

      // Verify both were stored
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(2);
    });

    it('should handle relations with different branch scopes', async () => {
      const relations = [
        {
          kind: 'relation' as const,
          scope: {
            project: 'test-project',
            branch: 'main',
          },
          data: {
            from_entity_type: 'feature',
            from_entity_id: '550e8400-e29b-41d4-a716-446655440000',
            to_entity_type: 'feature',
            to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
            relationType: 'depends_on',
          },
          content: 'Feature dependency in main branch',
        },
        {
          kind: 'relation' as const,
          scope: {
            project: 'test-project',
            branch: 'develop',
          },
          data: {
            from_entity_type: 'feature',
            from_entity_id: '550e8400-e29b-41d4-a716-446655440002',
            to_entity_type: 'feature',
            to_entity_id: '550e8400-e29b-41d4-a716-446655440003',
            relationType: 'conflicts_with',
          },
          content: 'Feature conflict in develop branch',
        },
      ];

      await db.storeItems(relations);
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(2);
    });
  });

  describe('Relation Edge Cases and Error Handling', () => {
    it('should handle relations with complex metadata', async () => {
      const complexRelation = {
        kind: 'relation' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          from_entity_type: 'decision',
          from_entity_id: '550e8400-e29b-41d4-a716-446655440000',
          to_entity_type: 'observation',
          to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
          relationType: 'validated_by',
          metadata: {
            weight: 0.95,
            confidence: 0.88,
            since: '2025-01-01',
            evidence: ['user_testing', 'performance_metrics', 'code_review'],
            context: {
              environment: 'production',
              version: '2.1.0',
              stakeholder: 'product-team',
            },
          },
        },
        content: 'Complex relation with rich metadata',
      };

      const result = await db.storeItems([complexRelation]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.metadata.weight).toBe(0.95);
      expect(result.stored[0].data.metadata.evidence).toHaveLength(3);
    });

    it('should handle self-referencing relations', async () => {
      const selfRelation = {
        kind: 'relation' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          from_entity_type: 'entity',
          from_entity_id: '550e8400-e29b-41d4-a716-446655440000',
          to_entity_type: 'entity',
          to_entity_id: '550e8400-e29b-41d4-a716-446655440000', // Same entity
          relationType: 'references',
        },
        content: 'Self-referencing relation',
      };

      const result = RelationSchema.safeParse(selfRelation);
      expect(result.success).toBe(true);
    });

    it('should handle relations with special characters in relationType', async () => {
      const relations = [
        {
          kind: 'relation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            from_entity_type: 'entity',
            from_entity_id: '550e8400-e29b-41d4-a716-446655440000',
            to_entity_type: 'entity',
            to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
            relationType: 'relates-to-via-API',
          },
          content: 'Relation with special characters',
        },
        {
          kind: 'relation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            from_entity_type: 'entity',
            from_entity_id: '550e8400-e29b-41d4-a716-446655440002',
            to_entity_type: 'entity',
            to_entity_id: '550e8400-e29b-41d4-a716-446655440003',
            relationType: 'version_2_dependency',
          },
          content: 'Another relation with special characters',
        },
      ];

      const results = relations.map((relation) => RelationSchema.safeParse(relation));
      results.forEach((result) => {
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Relation Integration with Knowledge System', () => {
    it('should integrate with knowledge item validation', () => {
      const relation = {
        kind: 'relation' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          from_entity_type: 'incident',
          from_entity_id: '550e8400-e29b-41d4-a716-446655440000',
          to_entity_type: 'runbook',
          to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
          relationType: 'resolved_using',
          metadata: { success_rate: 0.95, time_to_resolution: '2h' },
        },
        tags: { graph_relation: true, verified: true },
        source: {
          actor: 'incident-commander',
          tool: 'incident-management-system',
          timestamp: '2025-01-01T00:00:00Z',
        },
        ttl_policy: 'long' as const,
      };

      const result = validateKnowledgeItem(relation);
      expect(result.kind).toBe('relation');
      expect(result.data.relationType).toBe('resolved_using');
      expect(result.tags.graph_relation).toBe(true);
      expect(result.source.actor).toBe('incident-commander');
      expect(result.ttl_policy).toBe('long');
    });

    it('should handle TTL policy for relations', async () => {
      const relation = {
        kind: 'relation' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          from_entity_type: 'temp-entity',
          from_entity_id: '550e8400-e29b-41d4-a716-446655440000',
          to_entity_type: 'temp-entity',
          to_entity_id: '550e8400-e29b-41d4-a716-446655440001',
          relationType: 'temporary_link',
        },
        ttl_policy: 'short' as const,
        content: 'Temporary relation with short TTL',
      };

      const result = await db.storeItems([relation]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].ttl_policy).toBe('short');
    });
  });
});
