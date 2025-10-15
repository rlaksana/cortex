/**
 * Integration tests for entity storage (10th knowledge type)
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { memoryStore } from '../../src/services/memory-store.js';
import { memoryFind } from '../../src/services/memory-find.js';
import { getPool, closePool } from '../../src/db/pool.js';

describe('Entity Storage Integration Tests', () => {
  beforeAll(async () => {
    // Ensure database connection
    const pool = getPool();
    await pool.query('SELECT 1');
  });

  afterAll(async () => {
    // Cleanup test data
    const pool = getPool();
    await pool.query('DELETE FROM knowledge_entity WHERE tags @> \'{"test": true}\'::jsonb');
    await closePool();
  });

  it('should store a flexible entity with user-defined schema', async () => {
    const result = await memoryStore([
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'user',
          name: 'test_user_1',
          data: {
            role: 'engineer',
            skills: ['TypeScript', 'PostgreSQL'],
            preferences: { theme: 'dark' },
          },
        },
        tags: { test: true },
      },
    ]);

    expect(result.stored).toHaveLength(1);
    expect(result.stored[0].kind).toBe('entity');
    expect(result.stored[0].status).toBe('inserted');
    expect(result.errors).toHaveLength(0);
  });

  it('should deduplicate entities with same content_hash', async () => {
    const entityData = {
      kind: 'entity',
      scope: { project: 'test', branch: 'test' },
      data: {
        entity_type: 'organization',
        name: 'test_org_1',
        data: {
          industry: 'technology',
          size: 'startup',
        },
      },
      tags: { test: true },
    };

    // Store once
    const result1 = await memoryStore([entityData]);
    expect(result1.stored[0].status).toBe('inserted');

    // Store again (should be idempotent)
    const result2 = await memoryStore([entityData]);
    expect(result2.stored[0].id).toBe(result1.stored[0].id);
  });

  it('should update entity when name matches but data differs', async () => {
    const entityName = 'test_user_2';

    // Store initial version
    await memoryStore([
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'user',
          name: entityName,
          data: { version: 1 },
        },
        tags: { test: true },
      },
    ]);

    // Update with new data
    const result = await memoryStore([
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'user',
          name: entityName,
          data: { version: 2, updated: true },
        },
        tags: { test: true },
      },
    ]);

    expect(result.stored[0].status).toBe('inserted'); // Updated via INSERT OR UPDATE logic
  });

  it('should search entities by entity_type', async () => {
    // Store test entities
    await memoryStore([
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'goal',
          name: 'test_goal_1',
          data: { description: 'Learn Rust', target_date: '2025-12-31' },
        },
        tags: { test: true },
      },
    ]);

    // Search
    const result = await memoryFind({
      query: 'goal',
      types: ['entity'],
    });

    expect(result.hits.length).toBeGreaterThan(0);
    const goalEntity = result.hits.find((h) => h.title?.includes('goal'));
    expect(goalEntity).toBeDefined();
  });

  it('should search entities by name pattern', async () => {
    // Store entity with specific name
    await memoryStore([
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'preference',
          name: 'coding_style_python',
          data: { style: 'black', type_hints: true },
        },
        tags: { test: true },
      },
    ]);

    // Search by name
    const result = await memoryFind({
      query: 'coding_style',
      types: ['entity'],
    });

    expect(result.hits.length).toBeGreaterThan(0);
    const preference = result.hits.find((h) => h.title?.includes('coding_style'));
    expect(preference).toBeDefined();
  });

  it('should search entities by data content (JSONB search)', async () => {
    // Store entity with searchable data
    await memoryStore([
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'project',
          name: 'test_project_1',
          data: {
            name: 'cortex-memory',
            description: 'Knowledge graph for AI agents',
            tech_stack: ['TypeScript', 'PostgreSQL'],
          },
        },
        tags: { test: true },
      },
    ]);

    // Search by data content
    const result = await memoryFind({
      query: 'cortex-memory',
      types: ['entity'],
    });

    expect(result.hits.length).toBeGreaterThan(0);
    const project = result.hits.find((h) => h.snippet?.includes('cortex'));
    expect(project).toBeDefined();
  });

  it('should respect scope filtering for entities', async () => {
    // Store entities in different branches
    await memoryStore([
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'branch_a' },
        data: {
          entity_type: 'feature',
          name: 'feature_a',
          data: { description: 'Feature A' },
        },
        tags: { test: true },
      },
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'branch_b' },
        data: {
          entity_type: 'feature',
          name: 'feature_b',
          data: { description: 'Feature B' },
        },
        tags: { test: true },
      },
    ]);

    // Search with branch_a scope filter
    const result = await memoryFind({
      query: 'feature',
      types: ['entity'],
      scope: { project: 'test', branch: 'branch_a' },
    });

    // Should only return feature_a
    const titles = result.hits.map((h) => h.title);
    expect(titles.some((t) => t?.includes('feature_a'))).toBe(true);
    expect(titles.every((t) => !t?.includes('feature_b'))).toBe(true);
  });

  it('should reject invalid entity schemas', async () => {
    const result = await memoryStore([
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'test' },
        data: {
          // Missing required fields: entity_type, name
          data: { some: 'data' },
        },
        tags: { test: true },
      } as any,
    ]);

    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].error_code).toBe('INVALID_SCHEMA');
    expect(result.stored).toHaveLength(0);
  });

  it('should handle large entity data (stress test)', async () => {
    const largeData: Record<string, unknown> = {};
    for (let i = 0; i < 100; i++) {
      largeData[`field_${i}`] = `value_${i}`.repeat(10);
    }

    const result = await memoryStore([
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'large_entity',
          name: 'large_test',
          data: largeData,
        },
        tags: { test: true },
      },
    ]);

    expect(result.stored).toHaveLength(1);
    expect(result.errors).toHaveLength(0);
  });
});
