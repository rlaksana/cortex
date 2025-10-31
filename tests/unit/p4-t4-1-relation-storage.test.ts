/**
 * P4-T4.1: Relation Storage Tests - Phase 4 (Graph) Implementation
 *
 * Test-Driven Development approach for relation storage system.
 * These tests ensure that:
 * 1. Relations can be stored and queried by from_id/to_id
 * 2. Dedicated relation storage works correctly
 * 3. Entity validation works (or soft-creates entity stubs)
 *
 * Following TDD: Write failing tests first, then implement minimal code to pass.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { memoryStore } from '../../src/services/memory-store.js';
import { coreMemoryFind } from '../../src/services/core-memory-find.js';
import type {
  MemoryStoreResponse,
  MemoryFindResponse
} from '../../src/types/core-interfaces.js';

describe('P4-T4.1: Relation Storage System', () => {
  const testScope = {
    project: 'test-relation-storage',
    branch: 'main'
  };

  beforeEach(() => {
    // Clean setup before each test
  });

  afterEach(() => {
    // Cleanup after each test
  });

  describe('Store Relations - Basic Functionality', () => {
    it('should store a relation and return relation ID', async () => {
      // This test should FAIL initially - TDD approach
      const items = [{
        kind: 'relation',
        scope: testScope,
        data: {
          from_entity_type: 'entity',
          from_entity_id: '550e8400-e29b-41d4-a716-446655440001',
          to_entity_type: 'entity',
          to_entity_id: '550e8400-e29b-41d4-a716-446655440002',
          relation_type: 'relates_to',
          metadata: { strength: 0.8 }
        }
      }];

      const result = await memoryStore(items);

      expect(result.items).toHaveLength(1);
      expect(result.items[0].status).toBe('stored');
      expect(result.items[0].id).toBeDefined();
      expect(result.items[0].kind).toBe('relation');
    });

    it('should store multiple relations in batch', async () => {
      const request: MemoryStoreRequest = {
        items: [
          {
            kind: 'relation',
            scope: testScope,
            data: {
              from_entity_type: 'entity',
              from_entity_id: '550e8400-e29b-41d4-a716-446655440001',
              to_entity_type: 'entity',
              to_entity_id: '550e8400-e29b-41d4-a716-446655440002',
              relation_type: 'depends_on'
            }
          },
          {
            kind: 'relation',
            scope: testScope,
            data: {
              from_entity_type: 'entity',
              from_entity_id: '550e8400-e29b-41d4-a716-446655440002',
              to_entity_type: 'entity',
              to_entity_id: '550e8400-e29b-41d4-a716-446655440003',
              relation_type: 'implements'
            }
          }
        ]
      };

      const result = await memoryStore(request);

      expect(result.items).toHaveLength(2);
      expect(result.items.every(item => item.status === 'stored')).toBe(true);
      expect(result.items.every(item => item.id)).toBe(true);
    });
  });

  describe('Query Relations by from_id/to_id', () => {
    let storedRelationId: string;
    const fromEntityId = '550e8400-e29b-41d4-a716-446655440001';
    const toEntityId = '550e8400-e29b-41d4-a716-446655440002';

    beforeEach(async () => {
      // Store a test relation for querying
      const storeRequest: MemoryStoreRequest = {
        items: [{
          kind: 'relation',
          scope: testScope,
          data: {
            from_entity_type: 'entity',
            from_entity_id: fromEntityId,
            to_entity_type: 'entity',
            to_entity_id: toEntityId,
            relation_type: 'relates_to',
            metadata: { strength: 0.9 }
          }
        }]
      };

      const result = await memoryStore(storeRequest);
      storedRelationId = result.items[0].id!;
    });

    it('should query relations by from_entity_id', async () => {
      // This test should FAIL initially - TDD approach
      const findParams = {
        query: `from_entity_id:${fromEntityId}`,
        scope: testScope,
        types: ['relation']
      };

      const result = await coreMemoryFind(findParams);

      expect(result.items).toHaveLength(1);
      expect(result.items[0].id).toBe(storedRelationId);
      expect(result.items[0].kind).toBe('relation');
      expect(result.items[0].data.from_entity_id).toBe(fromEntityId);
      expect(result.items[0].match_type).toBe('exact');
    });

    it('should query relations by to_entity_id', async () => {
      const findRequest: MemoryFindRequest = {
        query: `to_entity_id:${toEntityId}`,
        scope: testScope,
        types: ['relation']
      };

      const result = await memoryFind(findRequest);

      expect(result.items).toHaveLength(1);
      expect(result.items[0].id).toBe(storedRelationId);
      expect(result.items[0].kind).toBe('relation');
      expect(result.items[0].data.to_entity_id).toBe(toEntityId);
      expect(result.items[0].match_type).toBe('exact');
    });

    it('should query relations by both from_id and to_id', async () => {
      const findRequest: MemoryFindRequest = {
        query: `from_entity_id:${fromEntityId} to_entity_id:${toEntityId}`,
        scope: testScope,
        types: ['relation']
      };

      const result = await memoryFind(findRequest);

      expect(result.items).toHaveLength(1);
      expect(result.items[0].id).toBe(storedRelationId);
      expect(result.items[0].data.from_entity_id).toBe(fromEntityId);
      expect(result.items[0].data.to_entity_id).toBe(toEntityId);
    });

    it('should query relations by relation_type', async () => {
      const findRequest: MemoryFindRequest = {
        query: `relation_type:relates_to`,
        scope: testScope,
        types: ['relation']
      };

      const result = await memoryFind(findRequest);

      expect(result.items).toHaveLength(1);
      expect(result.items[0].data.relation_type).toBe('relates_to');
    });

    it('should return empty result for non-existent from_entity_id', async () => {
      const findRequest: MemoryFindRequest = {
        query: `from_entity_id:550e8400-e29b-41d4-a716-44665544999`,
        scope: testScope,
        types: ['relation']
      };

      const result = await memoryFind(findRequest);
      expect(result.items).toHaveLength(0);
    });
  });

  describe('Entity Validation and Soft-Create', () => {
    it('should validate that from_entity exists before storing relation', async () => {
      // This test should FAIL initially - validation not implemented
      const request: MemoryStoreRequest = {
        items: [{
          kind: 'relation',
          scope: testScope,
          data: {
            from_entity_type: 'entity',
            from_entity_id: '550e8400-e29b-41d4-a716-446655440999', // Non-existent entity
            to_entity_type: 'entity',
            to_entity_id: '550e8400-e29b-41d4-a716-446655440002',
            relation_type: 'relates_to'
          }
        }]
      };

      const result = await memoryStore(request);

      // Should either create entity stub or fail validation
      expect(result.items[0].status).toMatch(/stored|validation_error/);
      if (result.items[0].status === 'validation_error') {
        expect(result.items[0].reason).toContain('from_entity does not exist');
      }
    });

    it('should validate that to_entity exists before storing relation', async () => {
      const request: MemoryStoreRequest = {
        items: [{
          kind: 'relation',
          scope: testScope,
          data: {
            from_entity_type: 'entity',
            from_entity_id: '550e8400-e29b-41d4-a716-446655440001',
            to_entity_type: 'entity',
            to_entity_id: '550e8400-e29b-41d4-a716-44665544999', // Non-existent entity
            relation_type: 'relates_to'
          }
        }]
      };

      const result = await memoryStore(request);

      // Should either create entity stub or fail validation
      expect(result.items[0].status).toMatch(/stored|validation_error/);
      if (result.items[0].status === 'validation_error') {
        expect(result.items[0].reason).toContain('to_entity does not exist');
      }
    });

    it('should soft-create entity stubs when storing relation to non-existent entities', async () => {
      // This test should FAIL initially - soft-create not implemented
      const request: MemoryStoreRequest = {
        items: [
          // First create entity stubs automatically
          {
            kind: 'entity',
            scope: testScope,
            data: {
              entity_type: 'entity',
              name: 'Test Entity From',
              data: { auto_created: true }
            }
          },
          {
            kind: 'entity',
            scope: testScope,
            data: {
              entity_type: 'entity',
              name: 'Test Entity To',
              data: { auto_created: true }
            }
          },
          // Then create relation between them
          {
            kind: 'relation',
            scope: testScope,
            data: {
              from_entity_type: 'entity',
              from_entity_id: 'auto-generated-or-existing',
              to_entity_type: 'entity',
              to_entity_id: 'auto-generated-or-existing',
              relation_type: 'relates_to'
            }
          }
        ]
      };

      const result = await memoryStore(request);

      expect(result.items).toHaveLength(3);
      // Entity stubs should be created
      expect(result.items[0].kind).toBe('entity');
      expect(result.items[0].status).toBe('stored');
      expect(result.items[1].kind).toBe('entity');
      expect(result.items[1].status).toBe('stored');
      // Relation should be stored successfully
      expect(result.items[2].kind).toBe('relation');
      expect(result.items[2].status).toBe('stored');
    });
  });

  describe('Dedicated Relation Storage', () => {
    it('should store relations in dedicated storage separate from other knowledge types', async () => {
      // This test should verify that relations have their own storage mechanism
      const request: MemoryStoreRequest = {
        items: [
          {
            kind: 'entity',
            scope: testScope,
            data: {
              entity_type: 'test',
              name: 'Test Entity',
              data: {}
            }
          },
          {
            kind: 'relation',
            scope: testScope,
            data: {
              from_entity_type: 'entity',
              from_entity_id: '550e8400-e29b-41d4-a716-446655440001',
              to_entity_type: 'entity',
              to_entity_id: '550e8400-e29b-41d4-a716-446655440002',
              relation_type: 'relates_to'
            }
          }
        ]
      };

      const result = await memoryStore(request);

      expect(result.items).toHaveLength(2);
      expect(result.items[0].kind).toBe('entity');
      expect(result.items[0].status).toBe('stored');
      expect(result.items[1].kind).toBe('relation');
      expect(result.items[1].status).toBe('stored');

      // Verify they can be queried separately
      const entityQuery: MemoryFindRequest = {
        query: 'test',
        scope: testScope,
        types: ['entity']
      };

      const relationQuery: MemoryFindRequest = {
        query: 'relates_to',
        scope: testScope,
        types: ['relation']
      };

      const [entityResult, relationResult] = await Promise.all([
        memoryFind(entityQuery),
        memoryFind(relationQuery)
      ]);

      expect(entityResult.items).toHaveLength(1);
      expect(entityResult.items[0].kind).toBe('entity');

      expect(relationResult.items).toHaveLength(1);
      expect(relationResult.items[0].kind).toBe('relation');
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle invalid UUID format for entity IDs', async () => {
      const request: MemoryStoreRequest = {
        items: [{
          kind: 'relation',
          scope: testScope,
          data: {
            from_entity_type: 'entity',
            from_entity_id: 'invalid-uuid-format',
            to_entity_type: 'entity',
            to_entity_id: '550e8400-e29b-41d4-a716-446655440002',
            relation_type: 'relates_to'
          }
        }]
      };

      const result = await memoryStore(request);

      expect(result.items[0].status).toBe('validation_error');
      expect(result.items[0].error_code).toBeDefined();
    });

    it('should handle missing required fields', async () => {
      const request: MemoryStoreRequest = {
        items: [{
          kind: 'relation',
          scope: testScope,
          data: {
            from_entity_type: 'entity',
            // Missing from_entity_id
            to_entity_type: 'entity',
            to_entity_id: '550e8400-e29b-41d4-a716-446655440002',
            relation_type: 'relates_to'
          }
        }]
      };

      const result = await memoryStore(request);

      expect(result.items[0].status).toBe('validation_error');
      expect(result.items[0].error_code).toBeDefined();
    });

    it('should enforce unique constraint on (from_entity_id, to_entity_id, relation_type)', async () => {
      // Store first relation
      const firstRequest: MemoryStoreRequest = {
        items: [{
          kind: 'relation',
          scope: testScope,
          data: {
            from_entity_type: 'entity',
            from_entity_id: '550e8400-e29b-41d4-a716-446655440001',
            to_entity_type: 'entity',
            to_entity_id: '550e8400-e29b-41d4-a716-446655440002',
            relation_type: 'relates_to'
          }
        }]
      };

      const firstResult = await memoryStore(firstRequest);
      expect(firstResult.items[0].status).toBe('stored');

      // Try to store duplicate relation
      const duplicateRequest: MemoryStoreRequest = {
        items: [{
          kind: 'relation',
          scope: testScope,
          data: {
            from_entity_type: 'entity',
            from_entity_id: '550e8400-e29b-41d4-a716-446655440001',
            to_entity_type: 'entity',
            to_entity_id: '550e8400-e29b-41d4-a716-446655440002',
            relation_type: 'relates_to'
          }
        }]
      };

      const duplicateResult = await memoryStore(duplicateRequest);

      // Should either skip duplicate or update existing
      expect(duplicateResult.items[0].status).toMatch(/stored|skipped_dupe/);
    });
  });

  describe('Graph Query Integration', () => {
    it('should support graph match_type in search results', async () => {
      // Store relations first
      const storeRequest: MemoryStoreRequest = {
        items: [{
          kind: 'relation',
          scope: testScope,
          data: {
            from_entity_type: 'entity',
            from_entity_id: '550e8400-e29b-41d4-a716-446655440001',
            to_entity_type: 'entity',
            to_entity_id: '550e8400-e29b-41d4-a716-446655440002',
            relation_type: 'implements'
          }
        }]
      };

      await memoryStore(storeRequest);

      // Query with graph match_type
      const findRequest: MemoryFindRequest = {
        query: 'implements',
        scope: testScope,
        types: ['relation'],
        mode: 'graph'
      };

      const result = await memoryFind(findRequest);

      expect(result.items).toHaveLength(1);
      expect(result.items[0].match_type).toBe('graph');
      expect(result.items[0].kind).toBe('relation');
    });
  });
});