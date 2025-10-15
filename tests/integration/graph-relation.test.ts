/**
 * Integration tests for relation storage (11th knowledge type)
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { memoryStore } from '../../src/services/memory-store.js';
import { getPool, closePool } from '../../src/db/pool.js';
import {
  getOutgoingRelations,
  getIncomingRelations,
  getAllRelations,
  relationExists,
} from '../../src/services/knowledge/relation.js';

describe('Relation Storage Integration Tests', () => {
  let testDecisionId: string;
  let testIssueId: string;

  beforeAll(async () => {
    // Setup: Create test entities
    const pool = getPool();
    await pool.query('SELECT 1');

    // Create test decision
    const decisionResult = await memoryStore([
      {
        kind: 'decision',
        scope: { project: 'test', branch: 'test' },
        data: {
          component: 'auth',
          status: 'proposed',
          title: 'Test Decision',
          rationale: 'Test rationale',
        },
        tags: { test: true },
      },
    ]);
    testDecisionId = decisionResult.stored[0].id;

    // Create test issue
    const issueResult = await memoryStore([
      {
        kind: 'issue',
        scope: { project: 'test', branch: 'test' },
        data: {
          tracker: 'github',
          external_id: 'TEST-123',
          title: 'Test Issue',
          status: 'open',
        },
        tags: { test: true },
      },
    ]);
    testIssueId = issueResult.stored[0].id;
  });

  afterAll(async () => {
    // Cleanup
    const pool = getPool();
    await pool.query('DELETE FROM knowledge_relation WHERE tags @> \'{"test": true}\'::jsonb');
    await pool.query('DELETE FROM adr_decision WHERE tags @> \'{"test": true}\'::jsonb');
    await pool.query('DELETE FROM issue_log WHERE tags @> \'{"test": true}\'::jsonb');
    await closePool();
  });

  it('should create a relation between two entities', async () => {
    const result = await memoryStore([
      {
        kind: 'relation',
        scope: { project: 'test', branch: 'test' },
        data: {
          from_entity_type: 'decision',
          from_entity_id: testDecisionId,
          to_entity_type: 'issue',
          to_entity_id: testIssueId,
          relation_type: 'resolves',
          metadata: { confidence: 0.95 },
        },
        tags: { test: true },
      },
    ]);

    expect(result.stored).toHaveLength(1);
    expect(result.stored[0].kind).toBe('relation');
    expect(result.stored[0].status).toBe('inserted');
    expect(result.errors).toHaveLength(0);
  });

  it('should prevent duplicate relations (unique constraint)', async () => {
    const relationData = {
      kind: 'relation' as const,
      scope: { project: 'test', branch: 'test' },
      data: {
        from_entity_type: 'decision',
        from_entity_id: testDecisionId,
        to_entity_type: 'issue',
        to_entity_id: testIssueId,
        relation_type: 'references',
      },
      tags: { test: true },
    };

    // Store once
    const result1 = await memoryStore([relationData]);
    expect(result1.stored[0].status).toBe('inserted');

    // Store again (should be idempotent - returns same ID)
    const result2 = await memoryStore([relationData]);
    expect(result2.stored[0].id).toBe(result1.stored[0].id);
  });

  it('should query outgoing relations from an entity', async () => {
    const pool = getPool();

    // Create relation
    await memoryStore([
      {
        kind: 'relation',
        scope: { project: 'test', branch: 'test' },
        data: {
          from_entity_type: 'decision',
          from_entity_id: testDecisionId,
          to_entity_type: 'issue',
          to_entity_id: testIssueId,
          relation_type: 'addresses',
        },
        tags: { test: true },
      },
    ]);

    // Query outgoing relations
    const relations = await getOutgoingRelations(pool, 'decision', testDecisionId);

    expect(relations.length).toBeGreaterThan(0);
    const addressesRelation = relations.find((r) => r.relation_type === 'addresses');
    expect(addressesRelation).toBeDefined();
    expect(addressesRelation?.to_entity_type).toBe('issue');
    expect(addressesRelation?.to_entity_id).toBe(testIssueId);
  });

  it('should query incoming relations to an entity', async () => {
    const pool = getPool();

    // Create relation
    await memoryStore([
      {
        kind: 'relation',
        scope: { project: 'test', branch: 'test' },
        data: {
          from_entity_type: 'decision',
          from_entity_id: testDecisionId,
          to_entity_type: 'issue',
          to_entity_id: testIssueId,
          relation_type: 'blocks',
        },
        tags: { test: true },
      },
    ]);

    // Query incoming relations to issue
    const relations = await getIncomingRelations(pool, 'issue', testIssueId);

    expect(relations.length).toBeGreaterThan(0);
    const blocksRelation = relations.find((r) => r.relation_type === 'blocks');
    expect(blocksRelation).toBeDefined();
    expect(blocksRelation?.from_entity_type).toBe('decision');
    expect(blocksRelation?.from_entity_id).toBe(testDecisionId);
  });

  it('should query all relations (bidirectional)', async () => {
    const pool = getPool();

    // Query all relations for decision
    const relations = await getAllRelations(pool, 'decision', testDecisionId);

    expect(relations.outgoing.length).toBeGreaterThan(0);
    // Incoming might be 0 if no relations point TO the decision
  });

  it('should filter relations by relation_type', async () => {
    const pool = getPool();

    // Create multiple relation types
    await memoryStore([
      {
        kind: 'relation',
        scope: { project: 'test', branch: 'test' },
        data: {
          from_entity_type: 'decision',
          from_entity_id: testDecisionId,
          to_entity_type: 'issue',
          to_entity_id: testIssueId,
          relation_type: 'supersedes',
        },
        tags: { test: true },
      },
    ]);

    // Query with filter
    const relations = await getOutgoingRelations(pool, 'decision', testDecisionId, 'supersedes');

    expect(relations.every((r) => r.relation_type === 'supersedes')).toBe(true);
  });

  it('should check relation existence', async () => {
    const pool = getPool();

    // Create relation
    await memoryStore([
      {
        kind: 'relation',
        scope: { project: 'test', branch: 'test' },
        data: {
          from_entity_type: 'decision',
          from_entity_id: testDecisionId,
          to_entity_type: 'issue',
          to_entity_id: testIssueId,
          relation_type: 'implements',
        },
        tags: { test: true },
      },
    ]);

    // Check existence
    const exists = await relationExists(
      pool,
      'decision',
      testDecisionId,
      'issue',
      testIssueId,
      'implements'
    );

    expect(exists).toBe(true);
  });

  it('should support relation metadata', async () => {
    const result = await memoryStore([
      {
        kind: 'relation',
        scope: { project: 'test', branch: 'test' },
        data: {
          from_entity_type: 'decision',
          from_entity_id: testDecisionId,
          to_entity_type: 'issue',
          to_entity_id: testIssueId,
          relation_type: 'depends_on',
          metadata: {
            weight: 0.8,
            confidence: 0.9,
            since: '2025-10-13',
            notes: 'Test metadata',
          },
        },
        tags: { test: true },
      },
    ]);

    expect(result.stored[0].status).toBe('inserted');

    // Query and verify metadata
    const pool = getPool();
    const relations = await getOutgoingRelations(pool, 'decision', testDecisionId, 'depends_on');
    const relation = relations.find((r) => r.relation_type === 'depends_on');

    expect(relation?.metadata).toBeDefined();
    expect(relation?.metadata).toMatchObject({
      weight: 0.8,
      confidence: 0.9,
      since: '2025-10-13',
    });
  });

  it('should support polymorphic relations (any type to any type)', async () => {
    // Create entity
    const entityResult = await memoryStore([
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'user',
          name: 'test_user_rel',
          data: { role: 'engineer' },
        },
        tags: { test: true },
      },
    ]);
    const userId = entityResult.stored[0].id;

    // Create relation: entity → decision
    const result = await memoryStore([
      {
        kind: 'relation',
        scope: { project: 'test', branch: 'test' },
        data: {
          from_entity_type: 'entity',
          from_entity_id: userId,
          to_entity_type: 'decision',
          to_entity_id: testDecisionId,
          relation_type: 'authored',
        },
        tags: { test: true },
      },
    ]);

    expect(result.stored[0].status).toBe('inserted');

    // Verify polymorphic relation
    const pool = getPool();
    const relations = await getOutgoingRelations(pool, 'entity', userId);
    expect(relations.some((r) => r.to_entity_type === 'decision')).toBe(true);
  });

  it('should reject invalid relation schemas', async () => {
    const result = await memoryStore([
      {
        kind: 'relation',
        scope: { project: 'test', branch: 'test' },
        data: {
          // Missing required fields
          from_entity_type: 'decision',
          // Missing from_entity_id, to_entity_type, to_entity_id, relation_type
        },
        tags: { test: true },
      } as any,
    ]);

    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].error_code).toBe('INVALID_SCHEMA');
    expect(result.stored).toHaveLength(0);
  });

  it('should handle invalid UUID in relation data', async () => {
    const result = await memoryStore([
      {
        kind: 'relation',
        scope: { project: 'test', branch: 'test' },
        data: {
          from_entity_type: 'decision',
          from_entity_id: 'not-a-valid-uuid',
          to_entity_type: 'issue',
          to_entity_id: testIssueId,
          relation_type: 'test',
        },
        tags: { test: true },
      },
    ]);

    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].error_code).toBe('INVALID_SCHEMA');
  });
});
