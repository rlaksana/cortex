/**
 * Comprehensive Unit Tests for Entity Knowledge Type
 *
 * Tests entity knowledge type functionality including:
 * - Entity validation with all required fields
 * - Flexible data schema validation
 * - Entity type constraints
 * - Name uniqueness and length limits
 * - Scope isolation
 * - Error handling and edge cases
 * - Constitutional requirements compliance
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { EntitySchema, validateKnowledgeItem } from '../../../src/schemas/knowledge-types';

// Declare global VectorDatabase mock
declare global {
  class VectorDatabase {
    client: any;
    constructor();
  }
}

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

describe('Entity Knowledge Type - Comprehensive Testing', () => {
  let db: VectorDatabase;
  let mockQdrant: any;

  beforeEach(() => {
    db = new VectorDatabase();
    mockQdrant = (db as any).client;
  });

  describe('Entity Schema Validation', () => {
    it('should validate complete entity with all fields', () => {
      const entity = {
        kind: 'entity' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          entity_type: 'user',
          name: 'john_doe',
          data: {
            email: 'john@example.com',
            role: 'developer',
            preferences: { theme: 'dark', language: 'en' },
          },
        },
        tags: { verified: true },
        source: {
          actor: 'test-actor',
          tool: 'test-tool',
          timestamp: '2025-01-01T00:00:00Z',
        },
      };

      const result = EntitySchema.safeParse(entity);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.kind']).toBe('entity');
        expect(result['data.data'].entity_type).toBe('user');
        expect(result['data.data'].name).toBe('john_doe');
        expect(result['data.data'].data).toEqual({
          email: 'john@example.com',
          role: 'developer',
          preferences: { theme: 'dark', language: 'en' },
        });
      }
    });

    it('should validate minimal entity with only required fields', () => {
      const entity = {
        kind: 'entity' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          entity_type: 'organization',
          name: 'Acme Corp',
          data: {},
        },
      };

      const result = EntitySchema.safeParse(entity);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.data'].entity_type).toBe('organization');
        expect(result['data.data'].data).toEqual({});
      }
    });

    it('should reject entity missing required fields', () => {
      const invalidEntities = [
        {
          kind: 'entity' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            // Missing entity_type
            name: 'test',
          },
        },
        {
          kind: 'entity' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: 'user',
            // Missing name
          },
        },
        {
          kind: 'entity' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: '',
            name: 'test', // Empty entity_type
          },
        },
        {
          kind: 'entity' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: 'user',
            name: '', // Empty name
          },
        },
      ];

      invalidEntities.forEach((entity, index) => {
        const result = EntitySchema.safeParse(entity);
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues.length).toBeGreaterThan(0);
        }
      });
    });

    it('should enforce entity_type length constraints', () => {
      const entity = {
        kind: 'entity' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          entity_type: 'x'.repeat(101), // Exceeds 100 character limit
          name: 'test',
          data: {},
        },
      };

      const result = EntitySchema.safeParse(entity);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('100 characters or less');
      }
    });

    it('should enforce name length constraints', () => {
      const entity = {
        kind: 'entity' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          entity_type: 'user',
          name: 'x'.repeat(501), // Exceeds 500 character limit
          data: {},
        },
      };

      const result = EntitySchema.safeParse(entity);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('500 characters or less');
      }
    });
  });

  describe('Entity Storage Operations', () => {
    it('should store entity successfully using memory_store pattern', async () => {
      const entity = {
        kind: 'entity' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          entity_type: 'user',
          name: 'test_user',
          data: { email: 'test@example.com' },
        },
        content: 'Entity: user named test_user with email test@example.com', // Required for embedding generation
      };

      const result = await db.storeItems([entity]);

      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      expect(result.stored[0]).toHaveProperty('id');
      expect(result.stored[0].kind).toBe('entity');
      expect(result.stored[0].data.entity_type).toBe('user');
      expect(result.stored[0].data.name).toBe('test_user');

      // Verify Qdrant client was called
      expect(mockQdrant.upsert).toHaveBeenCalled();
    });

    it('should handle batch entity storage successfully', async () => {
      const entities = Array.from({ length: 5 }, (_, i) => ({
        kind: 'entity' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          entity_type: 'user',
          name: `user_${i}`,
          data: { index: i, active: i % 2 === 0 },
        },
        content: `Entity: user named user_${i} with index ${i}`,
      }));

      const result = await db.storeItems(entities);

      expect(result.stored).toHaveLength(5);
      expect(result.errors).toHaveLength(0);
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(5);
    });

    it('should handle mixed valid and invalid entities in batch', async () => {
      const items = [
        {
          kind: 'entity' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: 'user',
            name: 'valid_user',
            data: {},
          },
          content: 'Entity: user named valid_user',
        },
        {
          kind: 'entity' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            // Missing entity_type
            name: 'invalid_entity',
          },
          content: 'Entity: invalid entity missing type',
        },
        {
          kind: 'entity' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: 'organization',
            name: 'valid_org',
            data: { employees: 100 },
          },
          content: 'Entity: organization named valid_org with 100 employees',
        },
      ];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(2); // 2 valid entities
      expect(result.errors).toHaveLength(1); // 1 invalid entity
    });
  });

  describe('Entity Search Operations', () => {
    beforeEach(() => {
      // Setup search mock for entities
      mockQdrant.search.mockResolvedValue([
        {
          id: 'entity-id-1',
          score: 0.9,
          payload: {
            kind: 'entity',
            data: {
              entity_type: 'user',
              name: 'john_doe',
              data: { email: 'john@example.com' },
            },
            scope: { project: 'test-project', branch: 'main' },
          },
        },
        {
          id: 'entity-id-2',
          score: 0.8,
          payload: {
            kind: 'entity',
            data: {
              entity_type: 'organization',
              name: 'Acme Corp',
              data: { industry: 'technology' },
            },
            scope: { project: 'test-project', branch: 'main' },
          },
        },
      ]);
    });

    it('should find entities by query', async () => {
      const query = 'john doe user';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[0].data.entity_type).toBe('user');
      expect(result.items[0].data.name).toBe('john_doe');
      expect(result.items[1].data.entity_type).toBe('organization');
      expect(result.items[1].data.name).toBe('Acme Corp');
      expect(mockQdrant.search).toHaveBeenCalled();
    });

    it('should handle empty entity search results', async () => {
      mockQdrant.search.mockResolvedValue([]);

      const result = await db.searchItems('nonexistent entity');

      expect(result.items).toHaveLength(0);
      expect(result.total).toBe(0);
    });
  });

  describe('Entity Scope Isolation', () => {
    it('should isolate entities by project scope', async () => {
      const entityProjectA = {
        kind: 'entity' as const,
        scope: {
          project: 'project-A',
          branch: 'main',
        },
        data: {
          entity_type: 'user',
          name: 'user_A',
          data: {},
        },
        content: 'Entity: user named user_A in project-A',
      };

      const entityProjectB = {
        kind: 'entity' as const,
        scope: {
          project: 'project-B',
          branch: 'main',
        },
        data: {
          entity_type: 'user',
          name: 'user_B',
          data: {},
        },
        content: 'Entity: user named user_B in project-B',
      };

      // Store both entities
      await db.storeItems([entityProjectA, entityProjectB]);

      // Verify both were stored
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(2);

      // Search with project scope filter (this would be implemented in the search logic)
      // For now, we're testing the storage isolation aspect
      const storedCalls = mockQdrant.upsert.mock.calls;
      expect(storedCalls[0][0].points[0].payload.scope.project).toBe('project-A');
      expect(storedCalls[1][0].points[0].payload.scope.project).toBe('project-B');
    });

    it('should handle entities with different branch scopes', async () => {
      const entities = [
        {
          kind: 'entity' as const,
          scope: {
            project: 'test-project',
            branch: 'main',
          },
          data: {
            entity_type: 'feature',
            name: 'main_feature',
            data: {},
          },
          content: 'Entity: feature named main_feature in main branch',
        },
        {
          kind: 'entity' as const,
          scope: {
            project: 'test-project',
            branch: 'develop',
          },
          data: {
            entity_type: 'feature',
            name: 'dev_feature',
            data: {},
          },
          content: 'Entity: feature named dev_feature in develop branch',
        },
      ];

      await db.storeItems(entities);

      expect(mockQdrant.upsert).toHaveBeenCalledTimes(2);
      const storedCalls = mockQdrant.upsert.mock.calls;
      expect(storedCalls[0][0][0].payload.scope.branch).toBe('main');
      expect(storedCalls[1][0][0].payload.scope.branch).toBe('develop');
    });
  });

  describe('Entity Edge Cases and Error Handling', () => {
    it('should handle entities with complex nested data', async () => {
      const complexEntity = {
        kind: 'entity' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          entity_type: 'configuration',
          name: 'complex_config',
          data: {
            nested: {
              level1: {
                level2: {
                  level3: {
                    deep_value: 'found',
                    array: [1, 2, 3, { nested: true }],
                  },
                },
              },
            },
            large_object: {
              // Test with large object
              keys: Array.from({ length: 100 }, (_, i) => `key_${i}`),
              values: Array.from({ length: 100 }, (_, i) => ({ value: i, active: i % 2 === 0 })),
            },
          },
        },
      };

      const result = await db.storeItems([complexEntity]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data['data.nested'].level1.level2.level3.deep_value).toBe('found');
    });

    it('should handle entities with special characters in name', async () => {
      const entities = [
        {
          kind: 'entity' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: 'user',
            name: 'user-with-dashes',
            data: {},
          },
        },
        {
          kind: 'entity' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: 'user',
            name: 'user_with_underscores',
            data: {},
          },
        },
        {
          kind: 'entity' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: 'user',
            name: 'user.with.dots',
            data: {},
          },
        },
      ];

      const result = await db.storeItems(entities);

      expect(result.stored).toHaveLength(3);
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(3);
    });

    it('should handle entity storage errors gracefully', async () => {
      const entity = {
        kind: 'entity' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          entity_type: 'user',
          name: 'test_user',
          data: {},
        },
      };

      // Mock upsert to throw an error
      mockQdrant.upsert.mockRejectedValue(new Error('Connection timeout'));

      const result = await db.storeItems([entity]);

      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toContain('Connection timeout');
    });
  });

  describe('Entity Integration with Knowledge System', () => {
    it('should integrate with knowledge item validation', () => {
      const entity = {
        kind: 'entity' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          entity_type: 'goal',
          name: 'increase_user_engagement',
          data: {
            target: '20%',
            timeline: 'Q2 2025',
            metrics: ['daily_active_users', 'session_duration'],
          },
        },
        tags: { priority: 'high', category: 'business' },
        source: {
          actor: 'product-manager',
          tool: 'planning-system',
          timestamp: '2025-01-01T00:00:00Z',
        },
      };

      const result = validateKnowledgeItem(entity);
      expect(result.kind).toBe('entity');
      expect(result['data.entity_type']).toBe('goal');
      expect(result.tags.priority).toBe('high');
      expect(result.source.actor).toBe('product-manager');
    });

    it('should handle TTL policy for entities', async () => {
      const entity = {
        kind: 'entity' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          entity_type: 'preference',
          name: 'user_session_data',
          data: { theme: 'dark', language: 'en' },
        },
        ttl_policy: 'short' as const,
      };

      const result = await db.storeItems([entity]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].ttl_policy).toBe('short');
    });
  });
});
