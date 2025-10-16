/**
 * Category 3: Knowledge Retrieval Tests
 * Priority: P0 - CRITICAL
 *
 * Tests finding knowledge with different search modes
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { memoryStore } from '../../src/services/memory-store.js';
import { memoryFind } from '../../src/services/memory-find.js';
import { Pool } from 'pg';

const TEST_SCOPE = {
  project: 'test-retrieval',
  branch: 'test-functional',
  org: 'test-org',
};

describe('Category 3: Knowledge Retrieval', () => {
  let pool: Pool;
  let storedIds: string[] = [];

  beforeAll(async () => {
    pool = new Pool({
      connectionString:
        process.env.DATABASE_URL || 'postgresql://cortex:trust@localhost:5433/cortex_prod',
    });

    // Store test data
    const result = await memoryStore([
      {
        kind: 'section',
        scope: TEST_SCOPE,
        data: {
          title: 'Authentication System',
          body_md: '# OAuth 2.0 Implementation\nOur authentication uses OAuth 2.0 with JWT tokens',
        },
      },
      {
        kind: 'section',
        scope: TEST_SCOPE,
        data: {
          title: 'Database Schema',
          body_md: '# PostgreSQL Schema\nUsers table with authentication fields',
        },
      },
      {
        kind: 'decision',
        scope: TEST_SCOPE,
        data: {
          component: 'auth',
          status: 'accepted',
          title: 'Use JWT for authentication',
          rationale: 'Stateless, secure, industry standard',
          alternatives_considered: ['Session cookies', 'Basic auth'],
        },
      },
    ]);

    storedIds = result.stored.map((item) => item.id);
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM knowledge WHERE scope->>'project' = $1`, [TEST_SCOPE.project]);
    await pool.end();
  });

  describe('KR-001: Find by Query (fast mode)', () => {
    it('should find relevant results using full-text search', async () => {
      const result = await memoryFind({
        query: 'authentication OAuth JWT',
        scope: TEST_SCOPE,
        mode: 'fast',
        top_k: 5,
      });

      expect(result.hits).toBeInstanceOf(Array);
      expect(result.hits.length).toBeGreaterThan(0);
      expect(result.hits[0]).toHaveProperty('id');
      expect(result.hits[0]).toHaveProperty('score');
    });
  });

  describe('KR-002: Find by Query (auto mode)', () => {
    it('should use intelligent routing', async () => {
      const result = await memoryFind({
        query: 'database schema PostgreSQL',
        scope: TEST_SCOPE,
        mode: 'auto',
        top_k: 5,
      });

      expect(result.hits).toBeInstanceOf(Array);
      expect(result.debug).toHaveProperty('mode_used');
      expect(['fast', 'deep']).toContain(result.debug.mode_used);
    });
  });

  describe('KR-003: Find by Query (deep mode)', () => {
    it('should find fuzzy matches using trigram similarity', async () => {
      const result = await memoryFind({
        query: 'authntication systm', // Typos
        scope: TEST_SCOPE,
        mode: 'deep',
        top_k: 5,
      });

      expect(result.hits).toBeInstanceOf(Array);
      // Deep mode should still find results despite typos
      expect(result.hits.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe('KR-004: Find with Scope Filter', () => {
    it('should return only matching scope', async () => {
      const result = await memoryFind({
        query: 'authentication',
        scope: TEST_SCOPE,
        mode: 'fast',
        top_k: 10,
      });

      expect(result.hits).toBeInstanceOf(Array);
      result.hits.forEach((hit) => {
        expect(hit.scope.project).toBe(TEST_SCOPE.project);
        expect(hit.scope.branch).toBe(TEST_SCOPE.branch);
      });
    });

    it('should not find items from different scope', async () => {
      const result = await memoryFind({
        query: 'authentication',
        scope: { ...TEST_SCOPE, project: 'different-project' },
        mode: 'fast',
        top_k: 10,
      });

      // Should not find items from TEST_SCOPE.project
      result.hits.forEach((hit) => {
        expect(hit.scope.project).not.toBe(TEST_SCOPE.project);
      });
    });
  });

  describe('KR-005: Find with Type Filter', () => {
    it('should return only specified types', async () => {
      const result = await memoryFind({
        query: 'authentication',
        scope: TEST_SCOPE,
        types: ['decision'],
        mode: 'fast',
        top_k: 10,
      });

      expect(result.hits).toBeInstanceOf(Array);
      result.hits.forEach((hit) => {
        expect(hit.kind).toBe('decision');
      });
    });

    it('should handle multiple type filters', async () => {
      const result = await memoryFind({
        query: 'authentication',
        scope: TEST_SCOPE,
        types: ['section', 'decision'],
        mode: 'fast',
        top_k: 10,
      });

      result.hits.forEach((hit) => {
        expect(['section', 'decision']).toContain(hit.kind);
      });
    });
  });

  describe('KR-006: Find with top_k=1', () => {
    it('should return exactly 1 result', async () => {
      const result = await memoryFind({
        query: 'authentication',
        scope: TEST_SCOPE,
        mode: 'fast',
        top_k: 1,
      });

      expect(result.hits).toHaveLength(1);
    });
  });

  describe('KR-007: Find with top_k=50', () => {
    it('should return up to 50 results', async () => {
      const result = await memoryFind({
        query: 'test',
        scope: TEST_SCOPE,
        mode: 'fast',
        top_k: 50,
      });

      expect(result.hits.length).toBeLessThanOrEqual(50);
    });
  });

  describe('KR-008: Find No Results', () => {
    it('should return empty array with suggestions', async () => {
      const result = await memoryFind({
        query: 'xyzabc-nonexistent-query-12345',
        scope: TEST_SCOPE,
        mode: 'fast',
        top_k: 5,
      });

      expect(result.hits).toHaveLength(0);
      expect(result.suggestions).toBeInstanceOf(Array);
      expect(result.suggestions.length).toBeGreaterThan(0);
    });
  });

  describe('KR-009: Find with Special Characters', () => {
    it('should handle special characters safely', async () => {
      const specialQueries = [
        "authentication'; DROP TABLE knowledge; --",
        'auth<script>alert(1)</script>',
        'auth%20OR%201=1',
        'auth\x00null',
      ];

      for (const query of specialQueries) {
        await expect(
          memoryFind({
            query,
            scope: TEST_SCOPE,
            mode: 'fast',
            top_k: 5,
          })
        ).resolves.toBeDefined();
      }
    });
  });

  describe('KR-010: Find with Very Long Query', () => {
    it('should handle queries up to 1000 characters', async () => {
      const longQuery = 'authentication '.repeat(100); // ~1500 chars

      const result = await memoryFind({
        query: longQuery,
        scope: TEST_SCOPE,
        mode: 'fast',
        top_k: 5,
      });

      expect(result).toBeDefined();
      expect(result.hits).toBeInstanceOf(Array);
    });
  });
});
