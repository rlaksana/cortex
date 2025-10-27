/**
 * Integration tests for observation management (12th knowledge type)
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { memoryStore } from '../services/memory-store.ts';
import { dbPool } from '../db/pool.ts';
import {
  getObservations,
  searchObservations,
  getObservationCount,
  deleteObservationsByText,
} from '../services/knowledge/observation.ts';

describe('Observation Management Integration Tests', () => {
  let testTaskId: string;

  beforeAll(async () => {
    // Setup: Create a test task
    const pool = dbPool;
    await pool.query('SELECT 1');

    const taskResult = await memoryStore([
      {
        kind: 'todo',
        scope: { project: 'test', branch: 'test' },
        data: {
          scope: 'test',
          todo_type: 'task',
          text: 'Test task for observations',
          status: 'open',
        },
        tags: { test: true },
      },
    ]);
    testTaskId = taskResult.stored[0].id;
  });

  afterAll(async () => {
    // Cleanup
    const pool = dbPool;
    await pool.query('DELETE FROM knowledge_observation WHERE entity_id = $1', [testTaskId]);
    await pool.query('DELETE FROM todo_log WHERE id = $1', [testTaskId]);
    // Don't close the shared pool in tests;
  });

  it('should add an observation to an entity', async () => {
    const result = await memoryStore([
      {
        kind: 'observation',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'todo',
          entity_id: testTaskId,
          observation: 'status: in_progress',
          observation_type: 'status',
        },
        tags: { test: true },
      },
    ]);

    expect(result.stored).toHaveLength(1);
    expect(result.stored[0].kind).toBe('observation');
    expect(result.stored[0].status).toBe('inserted');
    expect(result.errors).toHaveLength(0);
  });

  it('should append multiple observations (not replace)', async () => {
    // Add first observation
    await memoryStore([
      {
        kind: 'observation',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'todo',
          entity_id: testTaskId,
          observation: 'progress: 25%',
          observation_type: 'progress',
        },
        tags: { test: true },
      },
    ]);

    // Add second observation
    await memoryStore([
      {
        kind: 'observation',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'todo',
          entity_id: testTaskId,
          observation: 'progress: 50%',
          observation_type: 'progress',
        },
        tags: { test: true },
      },
    ]);

    // Retrieve all observations
    const pool = dbPool;
    const observations = await getObservations(pool, 'todo', testTaskId);

    // Should have multiple observations (append-only)
    expect(observations.length).toBeGreaterThanOrEqual(2);
    expect(observations.some((o) => o.observation.includes('25%'))).toBe(true);
    expect(observations.some((o) => o.observation.includes('50%'))).toBe(true);
  });

  it('should filter observations by observation_type', async () => {
    // Add observations with different types
    await memoryStore([
      {
        kind: 'observation',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'todo',
          entity_id: testTaskId,
          observation: 'assignee: john_doe',
          observation_type: 'assignment',
        },
        tags: { test: true },
      },
      {
        kind: 'observation',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'todo',
          entity_id: testTaskId,
          observation: 'This is a note',
          observation_type: 'note',
        },
        tags: { test: true },
      },
    ]);

    // Query with filter
    const pool = dbPool;
    const notes = await getObservations(pool, 'todo', testTaskId, 'note');

    expect(notes.every((o) => o.observation_type === 'note')).toBe(true);
    expect(notes.some((o) => o.observation.includes('This is a note'))).toBe(true);
  });

  it('should support observation metadata', async () => {
    const result = await memoryStore([
      {
        kind: 'observation',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'todo',
          entity_id: testTaskId,
          observation: 'priority: high',
          observation_type: 'priority',
          metadata: {
            source: 'user',
            confidence: 0.95,
            timestamp: '2025-10-13T12:00:00Z',
          },
        },
        tags: { test: true },
      },
    ]);

    expect(result.stored[0].status).toBe('inserted');

    // Retrieve and verify metadata
    const pool = dbPool;
    const observations = await getObservations(pool, 'todo', testTaskId, 'priority');

    const priorityObs = observations.find((o) => o.observation.includes('priority: high'));
    expect(priorityObs?.metadata).toBeDefined();
    expect(priorityObs?.metadata).toMatchObject({
      source: 'user',
      confidence: 0.95,
    });
  });

  it('should search observations by text (FTS)', async () => {
    // Add searchable observation
    await memoryStore([
      {
        kind: 'observation',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'todo',
          entity_id: testTaskId,
          observation: 'Completed authentication implementation with OAuth2',
          observation_type: 'note',
        },
        tags: { test: true },
      },
    ]);

    // Search
    const pool = dbPool;
    const results = await searchObservations(pool, 'authentication OAuth2');

    expect(results.length).toBeGreaterThan(0);
    expect(results.some((o) => o.observation.includes('authentication'))).toBe(true);
  });

  it('should count observations for an entity', async () => {
    const pool = dbPool;
    const count = await getObservationCount(pool, 'todo', testTaskId);

    expect(count).toBeGreaterThan(0); // Should have multiple observations from previous tests
  });

  it('should soft delete observations', async () => {
    // Add observation
    const result = await memoryStore([
      {
        kind: 'observation',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'todo',
          entity_id: testTaskId,
          observation: 'temporary observation',
          observation_type: 'temp',
        },
        tags: { test: true },
      },
    ]);
    const obsId = result.stored[0].id;

    // Delete observation
    const deleteResult = await memoryStore([
      {
        operation: 'delete',
        kind: 'observation',
        id: obsId,
      } as any,
    ]);

    expect(deleteResult.stored[0].id).toBe(obsId);

    // Verify it's deleted (not returned in queries)
    const pool = dbPool;
    const observations = await getObservations(pool, 'todo', testTaskId, 'temp');

    expect(observations.every((o) => o.observation !== 'temporary observation')).toBe(true);
  });

  it('should delete observations by text match', async () => {
    const textToDelete = 'delete_me_observation_123';

    // Add observation
    await memoryStore([
      {
        kind: 'observation',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'todo',
          entity_id: testTaskId,
          observation: textToDelete,
          observation_type: 'test',
        },
        tags: { test: true },
      },
    ]);

    // Delete by text
    const pool = dbPool;
    const deletedCount = await deleteObservationsByText(pool, 'todo', testTaskId, textToDelete);

    expect(deletedCount).toBeGreaterThan(0);

    // Verify deleted
    const observations = await getObservations(pool, 'todo', testTaskId);
    expect(observations.every((o) => o.observation !== textToDelete)).toBe(true);
  });

  it('should order observations by created_at DESC (newest first)', async () => {
    const pool = dbPool;
    const observations = await getObservations(pool, 'todo', testTaskId);

    // Check ordering (assuming observations have different timestamps)
    if (observations.length > 1) {
      for (let i = 0; i < observations.length - 1; i++) {
        const current = new Date(observations[i].created_at);
        const next = new Date(observations[i + 1].created_at);
        expect(current.getTime()).toBeGreaterThanOrEqual(next.getTime());
      }
    }
  });

  it('should reject invalid observation schemas', async () => {
    const result = await memoryStore([
      {
        kind: 'observation',
        scope: { project: 'test', branch: 'test' },
        data: {
          // Missing required fields: entity_type, entity_id, observation
          observation_type: 'test',
        },
        tags: { test: true },
      } as any,
    ]);

    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].error_code).toBe('INVALID_SCHEMA');
    expect(result.stored).toHaveLength(0);
  });

  it('should handle concurrent observations gracefully', async () => {
    // Add multiple observations in parallel
    const promises = [];
    for (let i = 0; i < 5; i++) {
      promises.push(
        memoryStore([
          {
            kind: 'observation',
            scope: { project: 'test', branch: 'test' },
            data: {
              entity_type: 'todo',
              entity_id: testTaskId,
              observation: `concurrent_observation_${i}`,
              observation_type: 'concurrent',
            },
            tags: { test: true },
          },
        ])
      );
    }

    const results = await Promise.all(promises);

    // All should succeed
    expect(results.every((r) => r.stored.length === 1)).toBe(true);

    // Verify all were stored
    const pool = dbPool;
    const observations = await getObservations(pool, 'todo', testTaskId, 'concurrent');
    expect(observations.length).toBe(5);
  });
});
