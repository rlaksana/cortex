import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
// PostgreSQL import removed - now using Qdrant;

// Integration tests to verify database schema matches code expectations
describe('Database Schema Validation', () => {
  let pool: QdrantClient;

  beforeAll(async () => {
    pool = new QdrantClient({
      host: 'localhost',
      port: 5433,
      database: 'cortex_prod',
      user: 'cortex',
      password: '',
    });
  });

  afterAll(async () => {
    await pool.end();
  });

  describe('Section Table Schema', () => {
    it('should have all required columns with correct types', async () => {
      const result = await pool.query(`
        SELECT column_name, data_type, is_nullable, character_maximum_length
        FROM information_schema.columns
        WHERE table_name = 'section'
        ORDER BY ordinal_position
      `);

      const columns = result.rows;

      // Verify required columns exist
      const columnNames = columns.map((col) => col.column_name);
      expect(columnNames).toContain('id');
      expect(columnNames).toContain('title');
      expect(columnNames).toContain('heading');
      expect(columnNames).toContain('body_jsonb');
      expect(columnNames).toContain('content_hash');
      expect(columnNames).toContain('tags');

      // Verify column constraints
      const titleColumn = columns.find((col) => col.column_name === 'title');
      expect(titleColumn?.is_nullable).toBe('NO');
      expect(titleColumn?.character_maximum_length).toBe(500);

      const headingColumn = columns.find((col) => col.column_name === 'heading');
      expect(headingColumn?.is_nullable).toBe('NO');
      expect(headingColumn?.character_maximum_length).toBe(300);

      const bodyJsonbColumn = columns.find((col) => col.column_name === 'body_jsonb');
      expect(bodyJsonbColumn?.data_type).toBe('jsonb');

      const contentHashColumn = columns.find((col) => col.column_name === 'content_hash');
      expect(contentHashColumn?.data_type).toBe('text');
    });

    it('should support INSERT with both title and heading', async () => {
      const testTitle = 'Test Section Title';
      const testHeading = 'Test Section Heading';
      const testBody = { text: 'Test content', markdown: 'Test content' };
      const testTags = JSON.stringify({ project: 'test', branch: 'main' });

      const result = await pool.query(
        `INSERT INTO section (title, heading, body_jsonb, tags)
         VALUES ($1, $2, $3, $4) RETURNING id, title, heading`,
        [testTitle, testHeading, testBody, testTags]
      );

      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].title).toBe(testTitle);
      expect(result.rows[0].heading).toBe(testHeading);

      // Cleanup
      await pool.query('DELETE FROM section WHERE id = $1', [result.rows[0].id]);
    });

    it('should reject INSERT without title', async () => {
      await expect(
        pool.query(
          `INSERT INTO section (heading, body_jsonb, tags)
           VALUES ($1, $2, $3)`,
          ['Test Heading', { text: 'Test' }, '{}']
        )
      ).rejects.toThrow('null value in column "title"');
    });

    it('should reject INSERT without heading', async () => {
      await expect(
        pool.query(
          `INSERT INTO section (title, body_jsonb, tags)
           VALUES ($1, $2, $3)`,
          ['Test Title', { text: 'Test' }, '{}']
        )
      ).rejects.toThrow('null value in column "heading"');
    });
  });

  describe('ADR Decision Table Schema', () => {
    it('should have required columns with correct constraints', async () => {
      const result = await pool.query(`
        SELECT column_name, data_type, is_nullable, character_maximum_length
        FROM information_schema.columns
        WHERE table_name = 'adr_decision'
        ORDER BY ordinal_position
      `);

      const columns = result.rows;
      const columnNames = columns.map((col) => col.column_name);

      expect(columnNames).toContain('id');
      expect(columnNames).toContain('title');
      expect(columnNames).toContain('status');
      expect(columnNames).toContain('component');
      expect(columnNames).toContain('rationale');

      const titleColumn = columns.find((col) => col.column_name === 'title');
      expect(titleColumn?.is_nullable).toBe('NO');
      expect(titleColumn?.character_maximum_length).toBe(500);

      const statusColumn = columns.find((col) => col.column_name === 'status');
      expect(statusColumn?.is_nullable).toBe('NO');
    });
  });

  describe('Code-Database Schema Alignment', () => {
    it('should detect schema mismatches in INSERT statements', async () => {
      // This test specifically validates the fix for the title column issue
      const fs = require('fs');
      const path = require('path');

      // Read the memory-store.ts file
      const memoryStorePath = path.join(__dirname, '../../src/services/memory-store.ts');
      const memoryStoreContent = fs.readFileSync(memoryStorePath, 'utf8');

      // Check that the INSERT statement includes both title and heading
      const sectionInsertMatch = memoryStoreContent.match(
        /INSERT INTO section \(([^)]+)\) VALUES \(([^)]+)\) RETURNING/
      );

      expect(sectionInsertMatch).toBeTruthy();
      if (sectionInsertMatch) {
        const columns = sectionInsertMatch[1].split(',').map((col) => col.trim());
        const values = sectionInsertMatch[2].split(',').map((val) => val.trim());

        expect(columns).toContain('title');
        expect(columns).toContain('heading');
        expect(columns.length).toBe(values.length);

        // Verify title is mapped correctly
        const titleIndex = columns.indexOf('title');
        expect(values[titleIndex]).toBe('$2');
      }
    });
  });

  describe('Content Hash Indexes', () => {
    it('should have indexes for performance optimization', async () => {
      const result = await pool.query(`
        SELECT indexname, indexdef
        // PostgreSQL index check removed
        WHERE tablename = 'section'
        AND indexname LIKE '%content_hash%'
      `);

      // Should have at least one index on content_hash for deduplication
      expect(result.rows.length).toBeGreaterThan(0);
    });
  });

  describe('Tags JSON Structure', () => {
    it('should support JSON tags for scope filtering', async () => {
      const testScope = {
        project: 'test-project',
        branch: 'feature/test-branch',
        org: 'test-org',
      };

      const result = await pool.query(
        `INSERT INTO section (title, heading, body_jsonb, tags)
         VALUES ($1, $2, $3, $4) RETURNING id, tags`,
        ['Test Title', 'Test Heading', { text: 'Test' }, JSON.stringify(testScope)]
      );

      expect(result.rows).toHaveLength(1);
      const retrievedTags = JSON.parse(result.rows[0].tags);
      expect(retrievedTags).toEqual(testScope);

      // Cleanup
      await pool.query('DELETE FROM section WHERE id = $1', [result.rows[0].id]);
    });
  });
});
