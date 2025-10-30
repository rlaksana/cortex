/**
 * Comprehensive Unit Tests for Observation Knowledge Type
 *
 * Tests observation knowledge type functionality including:
 * - Fine-grained fact validation
 * - Entity reference validation
 * - Observation type constraints
 * - Metadata handling for observations
 * - Scope isolation for observations
 * - Error handling and edge cases
 * - Integration with entity observations
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { VectorDatabase } from '../../../src/index';
import { ObservationSchema, validateKnowledgeItem } from '../../../src/schemas/knowledge-types';

// Mock Qdrant client - reusing pattern from memory-store.test.ts
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

describe('Observation Knowledge Type - Comprehensive Testing', () => {
  let db: VectorDatabase;
  let mockQdrant: any;

  beforeEach(() => {
    db = new VectorDatabase();
    mockQdrant = (db as any).client;
  });

  describe('Observation Schema Validation', () => {
    it('should validate complete observation with all fields', () => {
      const observation = {
        kind: 'observation' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          entity_type: 'decision',
          entity_id: '550e8400-e29b-41d4-a716-446655440000',
          observation: 'status: completed',
          observationType: 'status',
          metadata: {
            source: 'automated-check',
            confidence: 0.95,
            timestamp: '2025-01-01T00:00:00Z'
          }
        },
        tags: { verified: true, automated: true },
        source: {
          actor: 'system-monitor',
          tool: 'health-checker',
          timestamp: '2025-01-01T00:00:00Z'
        }
      };

      const result = ObservationSchema.safeParse(observation);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.kind).toBe('observation');
        expect(result.data.data.entity_type).toBe('decision');
        expect(result.data.data.observation).toBe('status: completed');
        expect(result.data.data.observationType).toBe('status');
        expect(result.data.data.metadata.confidence).toBe(0.95);
      }
    });

    it('should validate minimal observation with only required fields', () => {
      const observation = {
        kind: 'observation' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          entity_type: 'entity',
          entity_id: '550e8400-e29b-41d4-a716-446655440000',
          observation: 'progress: 50%'
        }
      };

      const result = ObservationSchema.safeParse(observation);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.entity_type).toBe('entity');
        expect(result.data.data.observation).toBe('progress: 50%');
        expect(result.data.data.observationType).toBeUndefined();
        expect(result.data.data.metadata).toBeUndefined();
      }
    });

    it('should reject observation missing required fields', () => {
      const invalidObservations = [
        {
          kind: 'observation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            // Missing entity_type
            entity_id: '550e8400-e29b-41d4-a716-446655440000',
            observation: 'test observation'
          }
        },
        {
          kind: 'observation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: 'entity',
            // Missing entity_id
            observation: 'test observation'
          }
        },
        {
          kind: 'observation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: 'entity',
            entity_id: '550e8400-e29b-41d4-a716-446655440000'
            // Missing observation
          }
        }
      ];

      invalidObservations.forEach((observation, index) => {
        const result = ObservationSchema.safeParse(observation);
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues.length).toBeGreaterThan(0);
        }
      });
    });

    it('should reject observation with invalid UUID format', () => {
      const observation = {
        kind: 'observation' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          entity_type: 'entity',
          entity_id: 'invalid-uuid-format', // Invalid UUID
          observation: 'test observation'
        }
      };

      const result = ObservationSchema.safeParse(observation);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('UUID');
      }
    });

    it('should enforce entity_type length constraints', () => {
      const observation = {
        kind: 'observation' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          entity_type: 'x'.repeat(101), // Exceeds 100 character limit
          entity_id: '550e8400-e29b-41d4-a716-446655440000',
          observation: 'test observation'
        }
      };

      const result = ObservationSchema.safeParse(observation);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('100 characters or less');
      }
    });
  });

  describe('Observation Storage Operations', () => {
    it('should store observation successfully using memory_store pattern', async () => {
      const observation = {
        kind: 'observation' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          entity_type: 'decision',
          entity_id: '550e8400-e29b-41d4-a716-446655440000',
          observation: 'status: implemented',
          observationType: 'status'
        },
        content: 'Observation: decision status implemented' // Required for embedding generation
      };

      const result = await db.storeItems([observation]);

      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      expect(result.stored[0]).toHaveProperty('id');
      expect(result.stored[0].kind).toBe('observation');
      expect(result.stored[0].data.observation).toBe('status: implemented');
      expect(result.stored[0].data.observationType).toBe('status');

      // Verify Qdrant client was called
      expect(mockQdrant.upsert).toHaveBeenCalled();
    });

    it('should handle batch observation storage successfully', async () => {
      const observations = Array.from({ length: 5 }, (_, i) => ({
        kind: 'observation' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          entity_type: 'entity',
          entity_id: '550e8400-e29b-41d4-a716-446655440000',
          observation: `metric: cpu_usage_${i * 20}%`,
          observationType: 'metric'
        },
        content: `Observation: entity cpu usage ${i * 20}%`
      }));

      const result = await db.storeItems(observations);

      expect(result.stored).toHaveLength(5);
      expect(result.errors).toHaveLength(0);
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(5);
    });

    it('should handle mixed valid and invalid observations in batch', async () => {
      const items = [
        {
          kind: 'observation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: 'runbook',
            entity_id: '550e8400-e29b-41d4-a716-446655440000',
            observation: 'status: verified',
            observationType: 'status'
          },
          content: 'Valid observation'
        },
        {
          kind: 'observation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: 'entity',
            // Missing entity_id
            observation: 'invalid observation'
          },
          content: 'Invalid observation'
        },
        {
          kind: 'observation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: 'decision',
            entity_id: '550e8400-e29b-41d4-a716-446655440001',
            observation: 'rationale: approved',
            observationType: 'rationale'
          },
          content: 'Another valid observation'
        }
      ];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(2); // 2 valid observations
      expect(result.errors).toHaveLength(1); // 1 invalid observation
    });
  });

  describe('Observation Search Operations', () => {
    beforeEach(() => {
      // Setup search mock for observations
      mockQdrant.search.mockResolvedValue([
        {
          id: 'observation-id-1',
          score: 0.9,
          payload: {
            kind: 'observation',
            data: {
              entity_type: 'decision',
              entity_id: '550e8400-e29b-41d4-a716-446655440000',
              observation: 'status: implemented',
              observationType: 'status'
            },
            scope: { project: 'test-project', branch: 'main' }
          }
        },
        {
          id: 'observation-id-2',
          score: 0.8,
          payload: {
            kind: 'observation',
            data: {
              entity_type: 'entity',
              entity_id: '550e8400-e29b-41d4-a716-446655440001',
              observation: 'progress: 75%',
              observationType: 'progress'
            },
            scope: { project: 'test-project', branch: 'main' }
          }
        }
      ]);
    });

    it('should find observations by query', async () => {
      const query = 'status implemented decision';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[0].data.observationType).toBe('status');
      expect(result.items[0].data.observation).toBe('status: implemented');
      expect(result.items[1].data.observationType).toBe('progress');
      expect(mockQdrant.search).toHaveBeenCalled();
    });

    it('should handle empty observation search results', async () => {
      mockQdrant.search.mockResolvedValue([]);

      const result = await db.searchItems('nonexistent observation');

      expect(result.items).toHaveLength(0);
      expect(result.total).toBe(0);
    });
  });

  describe('Observation Types', () => {
    it('should handle common observation types', async () => {
      const observationTypes = [
        'status',
        'progress',
        'note',
        'metric',
        'validation',
        'performance',
        'error',
        'warning'
      ];

      for (const observationType of observationTypes) {
        const observation = {
          kind: 'observation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: 'entity',
            entity_id: '550e8400-e29b-41d4-a716-446655440000',
            observation: `${observationType}: test value`,
            observationType
          },
          content: `Observation: ${observationType} test`
        };

        const result = ObservationSchema.safeParse(observation);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.data.observationType).toBe(observationType);
        }
      }
    });

    it('should handle observations without observationType', async () => {
      const observation = {
        kind: 'observation' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          entity_type: 'entity',
          entity_id: '550e8400-e29b-41d4-a716-446655440000',
          observation: 'custom: unspecified observation'
          // No observationType specified
        },
        content: 'Observation without type'
      };

      const result = ObservationSchema.safeParse(observation);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.observationType).toBeUndefined();
      }
    });
  });

  describe('Entity-Attached Observations', () => {
    it('should handle observations for different entity types', async () => {
      const entityTypes = [
        'decision', 'entity', 'relation', 'section', 'runbook',
        'change', 'issue', 'todo', 'release_note', 'ddl',
        'pr_context', 'incident', 'release', 'risk', 'assumption'
      ];

      for (const entityType of entityTypes) {
        const observation = {
          kind: 'observation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: entityType,
            entity_id: '550e8400-e29b-41d4-a716-446655440000',
            observation: `status: observed_${entityType}`
          },
          content: `Observation for ${entityType}`
        };

        const result = ObservationSchema.safeParse(observation);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.data.entity_type).toBe(entityType);
        }
      }
    });

    it('should handle multiple observations for the same entity', async () => {
      const entityId = '550e8400-e29b-41d4-a716-446655440000';
      const observations = [
        {
          kind: 'observation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: 'decision',
            entity_id: entityId,
            observation: 'status: proposed',
            observationType: 'status'
          },
          content: 'First observation'
        },
        {
          kind: 'observation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: 'decision',
            entity_id: entityId,
            observation: 'rationale: needs review',
            observationType: 'rationale'
          },
          content: 'Second observation'
        },
        {
          kind: 'observation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: 'decision',
            entity_id: entityId,
            observation: 'status: accepted',
            observationType: 'status'
          },
          content: 'Third observation'
        }
      ];

      const results = observations.map(obs => ObservationSchema.safeParse(obs));
      results.forEach(result => {
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Observation Scope Isolation', () => {
    it('should isolate observations by project scope', async () => {
      const observationProjectA = {
        kind: 'observation' as const,
        scope: {
          project: 'project-A',
          branch: 'main'
        },
        data: {
          entity_type: 'entity',
          entity_id: '550e8400-e29b-41d4-a716-446655440000',
          observation: 'status: active'
        },
        content: 'Observation in project-A'
      };

      const observationProjectB = {
        kind: 'observation' as const,
        scope: {
          project: 'project-B',
          branch: 'main'
        },
        data: {
          entity_type: 'entity',
          entity_id: '550e8400-e29b-41d4-a716-446655440001',
          observation: 'status: inactive'
        },
        content: 'Observation in project-B'
      };

      // Store both observations
      await db.storeItems([observationProjectA, observationProjectB]);

      // Verify both were stored
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(2);
    });
  });

  describe('Observation Edge Cases and Error Handling', () => {
    it('should handle observations with complex metadata', async () => {
      const complexObservation = {
        kind: 'observation' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          entity_type: 'entity',
          entity_id: '550e8400-e29b-41d4-a716-446655440000',
          observation: 'performance: comprehensive metrics collected',
          observationType: 'performance',
          metadata: {
            source: 'monitoring-system',
            confidence: 0.92,
            timestamp: '2025-01-01T00:00:00Z',
            metrics: {
              cpu_usage: 45.2,
              memory_usage: 67.8,
              response_time: 150,
              error_rate: 0.01
            },
            context: {
              environment: 'production',
              version: '2.1.0',
              region: 'us-west-2'
            }
          }
        },
        content: 'Complex observation with rich metadata'
      };

      const result = await db.storeItems([complexObservation]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.metadata.metrics.cpu_usage).toBe(45.2);
      expect(result.stored[0].data.metadata.context.environment).toBe('production');
    });

    it('should handle observations with special characters', async () => {
      const observations = [
        {
          kind: 'observation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: 'entity',
            entity_id: '550e8400-e29b-41d4-a716-446655440000',
            observation: 'error: Connection timeout after 30s (ETIMEDOUT)',
            observationType: 'error'
          },
          content: 'Observation with error message and code'
        },
        {
          kind: 'observation' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: 'entity',
            entity_id: '550e8400-e29b-41d4-a716-446655440001',
            observation: 'status: 🟢 Healthy (all systems operational)',
            observationType: 'status'
          },
          content: 'Observation with emoji and parentheses'
        }
      ];

      const results = observations.map(obs => ObservationSchema.safeParse(obs));
      results.forEach(result => {
        expect(result.success).toBe(true);
      });
    });

    it('should handle very long observation text', async () => {
      const longObservationText = 'x'.repeat(1000); // 1000 character observation
      const observation = {
        kind: 'observation' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          entity_type: 'entity',
          entity_id: '550e8400-e29b-41d4-a716-446655440000',
          observation: longObservationText
        },
        content: `Observation: ${longObservationText.substring(0, 50)}...`
      };

      const result = ObservationSchema.safeParse(observation);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.observation).toHaveLength(1000);
      }
    });
  });

  describe('Observation Integration with Knowledge System', () => {
    it('should integrate with knowledge item validation', () => {
      const observation = {
        kind: 'observation' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          entity_type: 'incident',
          entity_id: '550e8400-e29b-41d4-a716-446655440000',
          observation: 'resolution_time: 2h 15m',
          observationType: 'metric',
          metadata: { source: 'incident-tracking', automated: true }
        },
        tags: { verified: true, metric: true },
        source: {
          actor: 'incident-resolver',
          tool: 'incident-management',
          timestamp: '2025-01-01T00:00:00Z'
        },
        ttl_policy: 'default' as const
      };

      const result = validateKnowledgeItem(observation);
      expect(result.kind).toBe('observation');
      expect(result.data.observationType).toBe('metric');
      expect(result.tags.metric).toBe(true);
      expect(result.source.actor).toBe('incident-resolver');
      expect(result.ttl_policy).toBe('default');
    });

    it('should handle TTL policy for observations', async () => {
      const observation = {
        kind: 'observation' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          entity_type: 'temp-entity',
          entity_id: '550e8400-e29b-41d4-a716-446655440000',
          observation: 'temporary_status: checking'
        },
        ttl_policy: 'short' as const,
        content: 'Temporary observation with short TTL'
      };

      const result = await db.storeItems([observation]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].ttl_policy).toBe('short');
    });
  });
});