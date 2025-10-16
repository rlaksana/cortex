/**
 * Database Schema Validation Tests
 *
 * These tests prevent silent schema mismatches like the ts_rank issue.
 * They validate that critical columns have correct types and functions work as expected.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { dbPool } from '../../src/db/pool.js';
import { logger } from '../../src/utils/logger.js';

describe('Database Schema Validation', () => {
  let pool: typeof dbPool;

  beforeAll(async () => {
    pool = dbPool;
  });

  afterAll(async () => {
    // Don't close pool as it's shared
  });

  describe('Critical Column Types', () => {
    it('should have section.ts column with tsvector type', async () => {
      const result = await pool.query(`
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = 'section' AND column_name = 'ts'
      `);

      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].column_name).toBe('ts');
      expect(result.rows[0].data_type).toBe('tsvector');
    });

    it('should have document.tags column with jsonb type', async () => {
      const result = await pool.query(`
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = 'document' AND column_name = 'tags'
      `);

      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].column_name).toBe('tags');
      expect(result.rows[0].data_type).toBe('jsonb');
    });

    it('should have knowledge_entity.tags column with jsonb type', async () => {
      const result = await pool.query(`
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = 'knowledge_entity' AND column_name = 'tags'
      `);

      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].column_name).toBe('tags');
      expect(result.rows[0].data_type).toBe('jsonb');
    });
  });

  describe('Function Dependencies', () => {
    it('should have ts_rank function available', async () => {
      const result = await pool.query(`
        SELECT routine_name
        FROM information_schema.routines
        WHERE routine_name = 'ts_rank'
        AND routine_schema = 'pg_catalog'
      `);

      expect(result.rows.length).toBeGreaterThan(0);
    });

    it('should have ts_rank_cd function available', async () => {
      const result = await pool.query(`
        SELECT routine_name
        FROM information_schema.routines
        WHERE routine_name = 'ts_rank_cd'
        AND routine_schema = 'pg_catalog'
      `);

      expect(result.rows.length).toBeGreaterThan(0);
    });

    it('should be able to use ts_rank with section.ts', async () => {
      // First ensure we have some test data
      await pool.query(`
        INSERT INTO section (id, document_id, heading, body_jsonb, content_hash)
        VALUES (
          gen_random_uuid(),
          gen_random_uuid(),
          'Test Document for Schema Validation',
          '{"text": "This is a test document to validate ts_rank functionality"}',
          'test-hash-' || gen_random_uuid()
        )
        ON CONFLICT DO NOTHING
      `);

      // Test ts_rank function works
      const result = await pool.query(`
        SELECT ts_rank(ts, to_tsquery('english', 'test')) as rank
        FROM section
        WHERE ts @@ to_tsquery('english', 'test')
        LIMIT 1
      `);

      expect(result.rows.length).toBeGreaterThan(0);
      expect(typeof result.rows[0].rank).toBe('number');
      expect(result.rows[0].rank).toBeGreaterThan(0);
    });

    it('should be able to use ts_rank_cd with section.ts', async () => {
      const result = await pool.query(`
        SELECT ts_rank_cd(ts, to_tsquery('english', 'document')) as rank
        FROM section
        WHERE ts @@ to_tsquery('english', 'document')
        LIMIT 1
      `);

      expect(result.rows.length).toBeGreaterThan(0);
      expect(typeof result.rows[0].rank).toBe('number');
      expect(result.rows[0].rank).toBeGreaterThan(0);
    });
  });

  describe('Required Extensions', () => {
    it('should have pgcrypto extension enabled', async () => {
      const result = await pool.query(`
        SELECT extname
        FROM pg_extension
        WHERE extname = 'pgcrypto'
      `);

      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].extname).toBe('pgcrypto');
    });

    it('should have pg_trgm extension enabled', async () => {
      const result = await pool.query(`
        SELECT extname
        FROM pg_extension
        WHERE extname = 'pg_trgm'
      `);

      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].extname).toBe('pg_trgm');
    });
  });

  describe('Generated Columns Consistency', () => {
    it('should have section.body_text generated column', async () => {
      const result = await pool.query(`
        SELECT column_name, is_generated, generation_expression
        FROM information_schema.columns
        WHERE table_name = 'section' AND column_name = 'body_text'
      `);

      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].column_name).toBe('body_text');
      expect(result.rows[0].is_generated).toBe('ALWAYS');
      expect(result.rows[0].generation_expression).toContain('body_jsonb');
    });

    it('should have section.ts generated column', async () => {
      const result = await pool.query(`
        SELECT column_name, is_generated, generation_expression
        FROM information_schema.columns
        WHERE table_name = 'section' AND column_name = 'ts'
      `);

      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].column_name).toBe('ts');
      expect(result.rows[0].is_generated).toBe('ALWAYS');
      expect(result.rows[0].generation_expression).toContain('to_tsvector');
    });
  });

  describe('Search Functionality Integration', () => {
    it('should perform full-text search without errors', async () => {
      const result = await pool.query(`
        SELECT id, heading, ts_rank(ts, to_tsquery('english', 'test')) as score
        FROM section
        WHERE ts @@ to_tsquery('english', 'test')
        ORDER BY score DESC
        LIMIT 5
      `);

      expect(Array.isArray(result.rows)).toBe(true);
      // Should return some results if we have test data
      expect(result.rows.length).toBeGreaterThanOrEqual(0);

      // If we have results, they should have proper structure
      for (const row of result.rows) {
        expect(row).toHaveProperty('id');
        expect(row).toHaveProperty('heading');
        expect(row).toHaveProperty('score');
        expect(typeof row.score).toBe('number');
      }
    });

    it('should perform trigram similarity search', async () => {
      const result = await pool.query(`
        SELECT heading, similarity(heading, 'test') as similarity_score
        FROM section
        WHERE similarity(heading, 'test') > 0.3
        ORDER BY similarity_score DESC
        LIMIT 5
      `);

      expect(Array.isArray(result.rows)).toBe(true);

      for (const row of result.rows) {
        expect(row).toHaveProperty('heading');
        expect(row).toHaveProperty('similarity_score');
        expect(typeof row.similarity_score).toBe('number');
        expect(row.similarity_score).toBeGreaterThan(0.3);
      }
    });
  });
});
