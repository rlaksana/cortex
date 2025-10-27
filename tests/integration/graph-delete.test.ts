/**
 * Integration tests for delete operations
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { memoryStore } from '../services/memory-store.ts';
import { dbQdrantClient } from '../db/pool.ts';
import { softDelete, undelete } from '../services/delete-operations.ts';
import { softDeleteEntity } from '../services/knowledge/entity.ts';
import { relationExists } from '../services/knowledge/relation.ts';

describe('Delete Operations Integration Tests', () => {
  let testEntityId: string;
  let testRelationId: string;
  let testDecisionId: string;

  beforeAll(async () => {
    const pool = dbQdrantClient;
    await pool.query('SELECT 1');

    // Create test entities
    const entityResult = await memoryStore([
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'test_type',
          name: 'test_delete_entity',
          data: { value: 'test' },
        },
        tags: { test: true, delete_test: true },
      },
    ]);
    testEntityId = entityResult.stored[0].id;

    // Create test relation
    const relationResult = await memoryStore([
      {
        kind: 'relation',
        scope: { project: 'test', branch: 'test' },
        data: {
          from_entity_type: 'entity',
          from_entity_id: testEntityId,
          to_entity_type: 'entity',
          to_entity_id: testEntityId,
          relation_type: 'self_ref',
        },
        tags: { test: true, delete_test: true },
      },
    ]);
    testRelationId = relationResult.stored[0].id;

    // Create test decision (for immutability tests)
    const decisionResult = await memoryStore([
      {
        kind: 'decision',
        scope: { project: 'test', branch: 'test' },
        data: {
          component: 'test',
          status: 'proposed',
          title: 'Test Delete Decision',
          rationale: 'Test',
        },
        tags: { test: true, delete_test: true },
      },
    ]);
    testDecisionId = decisionResult.stored[0].id;
  });

  afterAll(async () => {
    const pool = dbQdrantClient;
    await pool.query(
      'DELETE FROM knowledge_relation WHERE tags @> \'{"test": true, "delete_test": true}\'::jsonb'
    );
    await pool.query(
      'DELETE FROM knowledge_entity WHERE tags @> \'{"test": true, "delete_test": true}\'::jsonb'
    );
    await pool.query(
      'DELETE FROM adr_decision WHERE tags @> \'{"test": true, "delete_test": true}\'::jsonb'
    );
    // Don't close the shared pool in tests;
  });

  it('should soft delete an entity via memory.store', async () => {
    // Create entity to delete
    const createResult = await memoryStore([
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'temp',
          name: 'temp_entity_1',
          data: { temp: true },
        },
        tags: { test: true, delete_test: true },
      },
    ]);
    const entityId = createResult.stored[0].id;

    // Delete entity
    const deleteResult = await memoryStore([
      {
        operation: 'delete',
        kind: 'entity',
        id: entityId,
      } as any,
    ]);

    expect(deleteResult.stored).toHaveLength(1);
    expect(deleteResult.stored[0].id).toBe(entityId);

    // Verify soft delete (deleted_at set)
    const pool = dbQdrantClient;
    const check = await pool.query('SELECT deleted_at FROM knowledge_entity WHERE id = $1', [
      entityId,
    ]);
    expect(check.rows[0].deleted_at).not.toBeNull();
  });

  it('should soft delete a relation', async () => {
    // Create relation to delete
    const createResult = await memoryStore([
      {
        kind: 'relation',
        scope: { project: 'test', branch: 'test' },
        data: {
          from_entity_type: 'entity',
          from_entity_id: testEntityId,
          to_entity_type: 'entity',
          to_entity_id: testEntityId,
          relation_type: 'temp_rel',
        },
        tags: { test: true, delete_test: true },
      },
    ]);
    const relationId = createResult.stored[0].id;

    // Delete relation
    const deleteResult = await memoryStore([
      {
        operation: 'delete',
        kind: 'relation',
        id: relationId,
      } as any,
    ]);

    expect(deleteResult.stored[0].id).toBe(relationId);

    // Verify deleted
    const pool = dbQdrantClient;
    const check = await pool.query('SELECT deleted_at FROM knowledge_relation WHERE id = $1', [
      relationId,
    ]);
    expect(check.rows[0].deleted_at).not.toBeNull();
  });

  it('should cascade delete relations when deleting entity', async () => {
    // Create entity and relations
    const entityResult = await memoryStore([
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'cascade_test',
          name: 'cascade_entity',
          data: {},
        },
        tags: { test: true, delete_test: true },
      },
    ]);
    const entityId = entityResult.stored[0].id;

    // Create outgoing relation
    await memoryStore([
      {
        kind: 'relation',
        scope: { project: 'test', branch: 'test' },
        data: {
          from_entity_type: 'entity',
          from_entity_id: entityId,
          to_entity_type: 'entity',
          to_entity_id: testEntityId,
          relation_type: 'cascade_out',
        },
        tags: { test: true, delete_test: true },
      },
    ]);

    // Create incoming relation
    await memoryStore([
      {
        kind: 'relation',
        scope: { project: 'test', branch: 'test' },
        data: {
          from_entity_type: 'entity',
          from_entity_id: testEntityId,
          to_entity_type: 'entity',
          to_entity_id: entityId,
          relation_type: 'cascade_in',
        },
        tags: { test: true, delete_test: true },
      },
    ]);

    // Delete entity with cascade
    const deleteResult = await memoryStore([
      {
        operation: 'delete',
        kind: 'entity',
        id: entityId,
        cascade_relations: true,
      } as any,
    ]);

    expect(deleteResult.stored[0].id).toBe(entityId);

    // Verify relations were cascaded
    const pool = dbQdrantClient;
    const outExists = await relationExists(
      pool,
      'entity',
      entityId,
      'entity',
      testEntityId,
      'cascade_out'
    );
    const inExists = await relationExists(
      pool,
      'entity',
      testEntityId,
      'entity',
      entityId,
      'cascade_in'
    );

    expect(outExists).toBe(false);
    expect(inExists).toBe(false);
  });

  it('should prevent deleting accepted ADRs (immutability)', async () => {
    // Update decision to accepted status
    const pool = dbQdrantClient;
    await pool.query('UPDATE adr_decision SET status = $1 WHERE id = $2', [
      'accepted',
      testDecisionId,
    ]);

    // Attempt to delete accepted ADR
    const deleteResult = await memoryStore([
      {
        operation: 'delete',
        kind: 'decision',
        id: testDecisionId,
      } as any,
    ]);

    // Should fail with immutability error
    expect(deleteResult.errors).toHaveLength(1);
    expect(deleteResult.errors[0].error_code).toBe('IMMUTABLE_ENTITY');
    expect(deleteResult.errors[0].message).toContain('immutability');
  });

  it('should allow deleting proposed ADRs', async () => {
    // Create proposed ADR
    const adrResult = await memoryStore([
      {
        kind: 'decision',
        scope: { project: 'test', branch: 'test' },
        data: {
          component: 'test',
          status: 'proposed',
          title: 'Deleteable ADR',
          rationale: 'Test',
        },
        tags: { test: true, delete_test: true },
      },
    ]);
    const adrId = adrResult.stored[0].id;

    // Delete proposed ADR (should succeed)
    const deleteResult = await memoryStore([
      {
        operation: 'delete',
        kind: 'decision',
        id: adrId,
      } as any,
    ]);

    expect(deleteResult.stored[0].id).toBe(adrId);
  });

  it('should undelete a soft-deleted entity', async () => {
    // Create and delete entity
    const createResult = await memoryStore([
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'undelete_test',
          name: 'undelete_entity',
          data: {},
        },
        tags: { test: true, delete_test: true },
      },
    ]);
    const entityId = createResult.stored[0].id;

    await memoryStore([
      {
        operation: 'delete',
        kind: 'entity',
        id: entityId,
      } as any,
    ]);

    // Undelete
    const pool = dbQdrantClient;
    const restored = await undelete(pool, 'entity', entityId);

    expect(restored).toBe(true);

    // Verify deleted_at is NULL
    const check = await pool.query('SELECT deleted_at FROM knowledge_entity WHERE id = $1', [
      entityId,
    ]);
    expect(check.rows[0].deleted_at).toBeNull();
  });

  it('should return not_found for non-existent entity', async () => {
    const fakeId = '00000000-0000-0000-0000-000000000000';

    const deleteResult = await memoryStore([
      {
        operation: 'delete',
        kind: 'entity',
        id: fakeId,
      } as any,
    ]);

    expect(deleteResult.errors).toHaveLength(1);
    expect(deleteResult.errors[0].error_code).toBe('NOT_FOUND');
  });

  it('should create audit trail for delete operations', async () => {
    // Create entity
    const createResult = await memoryStore([
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'audit_test',
          name: 'audit_delete',
          data: {},
        },
        tags: { test: true, delete_test: true },
      },
    ]);
    const entityId = createResult.stored[0].id;

    // Delete entity
    await memoryStore([
      {
        operation: 'delete',
        kind: 'entity',
        id: entityId,
      } as any,
    ]);

    // Check audit trail
    const pool = dbQdrantClient;
    const audit = await pool.query(
      'SELECT * FROM event_audit WHERE entity_type = $1 AND entity_id = $2 AND operation = $3',
      ['entity', entityId, 'DELETE']
    );

    expect(audit.rows.length).toBeGreaterThan(0);
  });

  it('should preserve entity data after soft delete (for audit)', async () => {
    const testData = { important: 'data', version: 1 };

    // Create entity
    const createResult = await memoryStore([
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'preserve_test',
          name: 'preserve_entity',
          data: testData,
        },
        tags: { test: true, delete_test: true },
      },
    ]);
    const entityId = createResult.stored[0].id;

    // Delete entity
    await memoryStore([
      {
        operation: 'delete',
        kind: 'entity',
        id: entityId,
      } as any,
    ]);

    // Verify data still exists (just marked deleted)
    const pool = dbQdrantClient;
    const check = await pool.query('SELECT data, deleted_at FROM knowledge_entity WHERE id = $1', [
      entityId,
    ]);

    expect(check.rows[0].data).toEqual(testData);
    expect(check.rows[0].deleted_at).not.toBeNull();
  });

  it('should handle bulk delete operations', async () => {
    // Create multiple entities
    const entities = [];
    for (let i = 0; i < 3; i++) {
      const result = await memoryStore([
        {
          kind: 'entity',
          scope: { project: 'test', branch: 'test' },
          data: {
            entity_type: 'bulk_test',
            name: `bulk_entity_${i}`,
            data: { index: i },
          },
          tags: { test: true, delete_test: true },
        },
      ]);
      entities.push(result.stored[0].id);
    }

    // Bulk delete
    const deleteResult = await memoryStore(
      entities.map((id) => ({
        operation: 'delete',
        kind: 'entity',
        id,
      })) as any
    );

    expect(deleteResult.stored.length).toBe(3);

    // Verify all deleted
    const pool = dbQdrantClient;
    for (const id of entities) {
      const check = await pool.query('SELECT deleted_at FROM knowledge_entity WHERE id = $1', [id]);
      expect(check.rows[0].deleted_at).not.toBeNull();
    }
  });
});
