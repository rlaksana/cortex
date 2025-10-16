import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { Pool } from 'pg';
import { memoryFind } from '../../src/services/memory-find.js';

/**
 * T032: FTS Search Test
 *
 * Validates:
 * - Sections with matching keywords return hits
 * - Relevance scores > 0
 * - Snippets contain highlighted matches
 * - Results ordered by score descending
 */
describe('memory.find Full-Text Search', () => {
  let pool: Pool;
  const testDocId = '123e4567-e89b-12d3-a456-426614174000';

  beforeAll(() => {
    pool = new Pool({
      connectionString:
        process.env.DATABASE_URL || 'postgresql://cortex:cortex@localhost:5432/cortex_test',
    });
  });

  afterAll(async () => {
    await pool.end();
  });

  beforeEach(async () => {
    // Clean up test data
    await pool.query('DELETE FROM section WHERE document_id = $1', [testDocId]);
  });

  it('should find sections with FTS keyword matches', async () => {
    // Insert test sections with keywords
    const testSections = [
      {
        heading: 'JWT Authentication',
        body_text: 'Our system uses JWT tokens for stateless authentication with OAuth integration',
        keywords: ['JWT', 'authentication', 'OAuth'],
      },
      {
        heading: 'OAuth Setup',
        body_text: 'Configure OAuth providers for social login with JWT token generation',
        keywords: ['OAuth', 'JWT'],
      },
      {
        heading: 'Database Schema',
        body_text: 'PostgreSQL schema design with UUID primary keys and JSONB columns',
        keywords: [], // No auth keywords
      },
    ];

    for (const section of testSections) {
      await pool.query(
        `INSERT INTO section (document_id, heading, body_jsonb, body_text, tags)
         VALUES ($1, $2, $3, $4, $5)`,
        [
          testDocId,
          section.heading,
          JSON.stringify({ content: section.body_text }),
          section.body_text,
          JSON.stringify({ test: true }),
        ]
      );
    }

    // Search for "JWT tokens"
    const result = await memoryFind({
      query: 'JWT tokens',
      types: ['section'],
      top_k: 10,
      mode: 'fast',
    });

    // Should find 2 sections with JWT keyword
    expect(result.hits.length).toBeGreaterThanOrEqual(2);

    // All hits should have positive scores
    result.hits.forEach((hit) => {
      expect(hit.score).toBeGreaterThan(0);
    });

    // Results should be ordered by score descending
    for (let i = 0; i < result.hits.length - 1; i++) {
      expect(result.hits[i].score).toBeGreaterThanOrEqual(result.hits[i + 1].score);
    }

    // Check hit structure
    const firstHit = result.hits[0];
    expect(firstHit.kind).toBe('section');
    expect(firstHit.id).toBeDefined();
    expect(firstHit.title).toBeDefined();
    expect(firstHit.snippet).toBeDefined();

    // Snippet should contain search terms
    const snippetsContainKeyword = result.hits.some(
      (hit) =>
        hit.snippet.toLowerCase().includes('jwt') || hit.snippet.toLowerCase().includes('token')
    );
    expect(snippetsContainKeyword).toBe(true);
  });

  it('should return empty results for non-matching query', async () => {
    // Insert test section
    await pool.query(
      `INSERT INTO section (document_id, heading, body_jsonb, body_text, tags)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        testDocId,
        'API Documentation',
        JSON.stringify({ content: 'REST API endpoints' }),
        'REST API endpoints',
        JSON.stringify({ test: true }),
      ]
    );

    // Search for completely unrelated term
    const result = await memoryFind({
      query: 'xyzabc123nonexistent',
      types: ['section'],
      top_k: 10,
      mode: 'fast',
    });

    expect(result.hits).toHaveLength(0);
    expect(result.suggestions).toBeDefined();
    expect(Array.isArray(result.suggestions)).toBe(true);
  });

  it('should respect top_k limit', async () => {
    // Insert 20 test sections
    for (let i = 0; i < 20; i++) {
      await pool.query(
        `INSERT INTO section (document_id, heading, body_jsonb, body_text, tags)
         VALUES ($1, $2, $3, $4, $5)`,
        [
          testDocId,
          `Section ${i}`,
          JSON.stringify({ content: `Authentication content ${i}` }),
          `Authentication content ${i}`,
          JSON.stringify({ test: true }),
        ]
      );
    }

    // Search with top_k=5
    const result = await memoryFind({
      query: 'authentication',
      types: ['section'],
      top_k: 5,
      mode: 'fast',
    });

    expect(result.hits.length).toBeLessThanOrEqual(5);
  });

  it('should include debug metadata', async () => {
    const result = await memoryFind({
      query: 'test query',
      types: ['section'],
      top_k: 10,
      mode: 'fast',
    });

    expect(result.debug).toBeDefined();
    expect(result.debug.query_duration_ms).toBeGreaterThan(0);
    expect(result.debug.total_candidates).toBeGreaterThanOrEqual(0);
    expect(Array.isArray(result.debug.filters_applied)).toBe(true);
  });
});
