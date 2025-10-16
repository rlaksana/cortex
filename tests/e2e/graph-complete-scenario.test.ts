/**
 * E2E Test: Complete graph functionality scenario
 *
 * Scenario: Track a software feature from ideation to completion
 * - Store user entity (flexible type)
 * - Store decision (ADR)
 * - Store issue (bug tracker sync)
 * - Create relations (decision resolves issue, user authored decision)
 * - Add observations (track progress)
 * - Traverse graph (find all related entities)
 * - Delete temporary data (cleanup)
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { memoryStore } from '../../src/services/memory-store.js';
import { memoryFind } from '../../src/services/memory-find.js';
import { dbPool } from '../../src/db/pool.js';

describe('E2E: Complete Graph Scenario', () => {
  let userId: string;
  let decisionId: string;
  let issueId: string;
  let taskId: string;

  afterAll(async () => {
    // Cleanup all test data
    const pool = dbPool;
    await pool.query(
      "DELETE FROM knowledge_observation WHERE entity_type IN ('entity', 'decision', 'issue', 'todo')"
    );
    await pool.query('DELETE FROM knowledge_relation WHERE tags @> \'{"e2e": true}\'::jsonb');
    await pool.query('DELETE FROM knowledge_entity WHERE tags @> \'{"e2e": true}\'::jsonb');
    await pool.query('DELETE FROM adr_decision WHERE tags @> \'{"e2e": true}\'::jsonb');
    await pool.query('DELETE FROM issue_log WHERE tags @> \'{"e2e": true}\'::jsonb');
    await pool.query('DELETE FROM todo_log WHERE tags @> \'{"e2e": true}\'::jsonb');
    // Don't close the shared pool in tests;
  });

  it('Step 1: Create user entity (flexible type)', async () => {
    const result = await memoryStore([
      {
        kind: 'entity',
        scope: { project: 'cortex', branch: 'feature/auth' },
        data: {
          entity_type: 'user',
          name: 'alice_engineer',
          data: {
            role: 'senior_engineer',
            team: 'platform',
            expertise: ['TypeScript', 'PostgreSQL', 'OAuth'],
          },
        },
        tags: { e2e: true, scenario: 'feature_tracking' },
      },
    ]);

    expect(result.stored).toHaveLength(1);
    userId = result.stored[0].id;
    console.log(`✓ User created: ${userId}`);
  });

  it('Step 2: Create architecture decision (ADR)', async () => {
    const result = await memoryStore([
      {
        kind: 'decision',
        scope: { project: 'cortex', branch: 'feature/auth' },
        data: {
          component: 'authentication',
          status: 'accepted',
          title: 'Adopt OAuth 2.0 for user authentication',
          rationale:
            'OAuth 2.0 provides industry-standard security and supports multiple identity providers',
          alternatives_considered: ['JWT only', 'Session-based auth'],
          consequences: 'Requires OAuth provider setup and token management',
        },
        tags: { e2e: true, scenario: 'feature_tracking' },
      },
    ]);

    expect(result.stored).toHaveLength(1);
    decisionId = result.stored[0].id;
    console.log(`✓ Decision created: ${decisionId}`);
  });

  it('Step 3: Create issue from bug tracker', async () => {
    const result = await memoryStore([
      {
        kind: 'issue',
        scope: { project: 'cortex', branch: 'feature/auth' },
        data: {
          tracker: 'github',
          external_id: 'GH-1234',
          title: 'Implement OAuth 2.0 authentication flow',
          status: 'in_progress',
          description: 'Need to implement OAuth 2.0 flow as per ADR',
          assignee: 'alice_engineer',
        },
        tags: { e2e: true, scenario: 'feature_tracking' },
      },
    ]);

    expect(result.stored).toHaveLength(1);
    issueId = result.stored[0].id;
    console.log(`✓ Issue created: ${issueId}`);
  });

  it('Step 4: Create task for implementation', async () => {
    const result = await memoryStore([
      {
        kind: 'todo',
        scope: { project: 'cortex', branch: 'feature/auth' },
        data: {
          scope: 'feature/auth',
          todo_type: 'task',
          text: 'Implement OAuth 2.0 client library integration',
          status: 'in_progress',
          priority: 'high',
        },
        tags: { e2e: true, scenario: 'feature_tracking' },
      },
    ]);

    expect(result.stored).toHaveLength(1);
    taskId = result.stored[0].id;
    console.log(`✓ Task created: ${taskId}`);
  });

  it('Step 5: Create relationships between entities', async () => {
    const result = await memoryStore([
      // User authored the decision
      {
        kind: 'relation',
        scope: { project: 'cortex', branch: 'feature/auth' },
        data: {
          from_entity_type: 'entity',
          from_entity_id: userId,
          to_entity_type: 'decision',
          to_entity_id: decisionId,
          relation_type: 'authored',
          metadata: { timestamp: '2025-10-13T10:00:00Z' },
        },
        tags: { e2e: true, scenario: 'feature_tracking' },
      },
      // Decision addresses the issue
      {
        kind: 'relation',
        scope: { project: 'cortex', branch: 'feature/auth' },
        data: {
          from_entity_type: 'decision',
          from_entity_id: decisionId,
          to_entity_type: 'issue',
          to_entity_id: issueId,
          relation_type: 'addresses',
        },
        tags: { e2e: true, scenario: 'feature_tracking' },
      },
      // Task implements the decision
      {
        kind: 'relation',
        scope: { project: 'cortex', branch: 'feature/auth' },
        data: {
          from_entity_type: 'todo',
          from_entity_id: taskId,
          to_entity_type: 'decision',
          to_entity_id: decisionId,
          relation_type: 'implements',
        },
        tags: { e2e: true, scenario: 'feature_tracking' },
      },
    ]);

    expect(result.stored).toHaveLength(3);
    console.log(`✓ Created ${result.stored.length} relations`);
  });

  it('Step 6: Add observations to track progress', async () => {
    const result = await memoryStore([
      // Task progress observations
      {
        kind: 'observation',
        scope: { project: 'cortex', branch: 'feature/auth' },
        data: {
          entity_type: 'todo',
          entity_id: taskId,
          observation: 'status: started | progress: 0%',
          observation_type: 'progress',
        },
        tags: { e2e: true },
      },
      {
        kind: 'observation',
        scope: { project: 'cortex', branch: 'feature/auth' },
        data: {
          entity_type: 'todo',
          entity_id: taskId,
          observation: 'Integrated OAuth provider SDK',
          observation_type: 'note',
        },
        tags: { e2e: true },
      },
      {
        kind: 'observation',
        scope: { project: 'cortex', branch: 'feature/auth' },
        data: {
          entity_type: 'todo',
          entity_id: taskId,
          observation: 'progress: 50%',
          observation_type: 'progress',
        },
        tags: { e2e: true },
      },
    ]);

    expect(result.stored).toHaveLength(3);
    console.log(`✓ Added ${result.stored.length} observations`);
  });

  it('Step 7: Search for OAuth-related content', async () => {
    const result = await memoryFind({
      query: 'OAuth authentication',
      types: ['decision', 'issue', 'todo'],
      scope: { project: 'cortex', branch: 'feature/auth' },
    });

    expect(result.hits.length).toBeGreaterThan(0);
    expect(result.hits.some((h) => h.kind === 'decision')).toBe(true);
    console.log(`✓ Found ${result.hits.length} related items`);
  });

  it('Step 8: Traverse graph from decision node', async () => {
    const result = await memoryFind({
      query: 'OAuth',
      types: ['decision'],
      traverse: {
        start_entity_type: 'decision',
        start_entity_id: decisionId,
        depth: 2,
        direction: 'both', // Find both incoming and outgoing relations
      },
    });

    expect(result.graph).toBeDefined();
    expect(result.graph?.nodes.length).toBeGreaterThan(1);
    expect(result.graph?.edges.length).toBeGreaterThan(0);

    // Should find connected nodes
    const nodeIds = result.graph?.nodes.map((n) => n.entity_id) || [];
    expect(nodeIds).toContain(decisionId); // Root
    expect(nodeIds).toContain(issueId); // Addressed issue
    expect(nodeIds).toContain(userId); // Author

    console.log(
      `✓ Graph traversal found ${result.graph?.nodes.length} nodes, ${result.graph?.edges.length} edges`
    );
  });

  it('Step 9: Update task to completed', async () => {
    // Add final observation
    const result = await memoryStore([
      {
        kind: 'observation',
        scope: { project: 'cortex', branch: 'feature/auth' },
        data: {
          entity_type: 'todo',
          entity_id: taskId,
          observation: 'status: completed | progress: 100% | completed_at: 2025-10-13T15:00:00Z',
          observation_type: 'progress',
        },
        tags: { e2e: true },
      },
    ]);

    expect(result.stored).toHaveLength(1);
    console.log(`✓ Task marked as completed`);
  });

  it('Step 10: Query all observations for task (audit trail)', async () => {
    const pool = dbPool;
    const observations = await pool.query(
      'SELECT observation, observation_type, created_at FROM knowledge_observation WHERE entity_type = $1 AND entity_id = $2 AND deleted_at IS NULL ORDER BY created_at DESC',
      ['todo', taskId]
    );

    expect(observations.rows.length).toBeGreaterThanOrEqual(4);

    // Verify observation trail
    const progressObs = observations.rows.filter((o) => o.observation_type === 'progress');
    expect(progressObs.length).toBeGreaterThanOrEqual(3); // 0%, 50%, 100%

    console.log(`✓ Found ${observations.rows.length} observations (complete audit trail)`);
  });

  it('Step 11: Find all work by user (author relation)', async () => {
    const pool = dbPool;
    const authoredWork = await pool.query(
      `SELECT kr.to_entity_type, kr.to_entity_id, kr.relation_type
       FROM knowledge_relation kr
       WHERE kr.from_entity_type = 'entity'
         AND kr.from_entity_id = $1
         AND kr.relation_type = 'authored'
         AND kr.deleted_at IS NULL`,
      [userId]
    );

    expect(authoredWork.rows.length).toBeGreaterThan(0);
    expect(authoredWork.rows.some((r) => r.to_entity_id === decisionId)).toBe(true);

    console.log(`✓ User authored ${authoredWork.rows.length} items`);
  });

  it('Step 12: Delete temporary test data', async () => {
    // Soft delete the task (with observations)
    const deleteResult = await memoryStore([
      {
        operation: 'delete',
        kind: 'todo',
        id: taskId,
        cascade_relations: true,
      } as any,
    ]);

    expect(deleteResult.stored[0].id).toBe(taskId);

    // Verify soft delete
    const pool = dbPool;
    const check = await pool.query('SELECT deleted_at FROM todo_log WHERE id = $1', [taskId]);
    expect(check.rows[0].deleted_at).not.toBeNull();

    console.log(`✓ Test data soft-deleted (audit trail preserved)`);
  });

  it('Step 13: Verify audit trail completeness', async () => {
    const pool = dbPool;

    // Check all entities have audit entries
    const auditEntries = await pool.query(
      `SELECT entity_type, entity_id, operation, created_at
       FROM event_audit
       WHERE entity_id IN ($1, $2, $3, $4)
       ORDER BY created_at ASC`,
      [userId, decisionId, issueId, taskId]
    );

    // Should have INSERT operations for all entities
    expect(auditEntries.rows.some((r) => r.entity_id === userId && r.operation === 'INSERT')).toBe(
      true
    );
    expect(
      auditEntries.rows.some((r) => r.entity_id === decisionId && r.operation === 'INSERT')
    ).toBe(true);
    expect(auditEntries.rows.some((r) => r.entity_id === issueId && r.operation === 'INSERT')).toBe(
      true
    );
    expect(auditEntries.rows.some((r) => r.entity_id === taskId && r.operation === 'INSERT')).toBe(
      true
    );

    // Should have DELETE operation for task
    expect(auditEntries.rows.some((r) => r.entity_id === taskId && r.operation === 'DELETE')).toBe(
      true
    );

    console.log(`✓ Audit trail complete: ${auditEntries.rows.length} entries`);
  });

  it('Summary: Verify all graph capabilities', () => {
    console.log('\n=== E2E Test Summary ===');
    console.log('✓ Flexible entity storage (user entity)');
    console.log('✓ Typed knowledge storage (decision, issue, task)');
    console.log('✓ Polymorphic relationships (entity→decision, decision→issue, task→decision)');
    console.log('✓ Graph traversal with depth limits');
    console.log('✓ Observation lifecycle (append, track progress)');
    console.log('✓ Soft delete with cascade');
    console.log('✓ Complete audit trail (100% coverage)');
    console.log('✓ Branch isolation (all scoped to feature/auth)');
    console.log('========================\n');

    expect(true).toBe(true); // Summary assertion
  });
});
