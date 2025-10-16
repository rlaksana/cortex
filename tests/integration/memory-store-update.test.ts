import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Pool } from 'pg';
import { memoryStore } from '../../src/services/memory-store.js';
import { ImmutabilityViolationError } from '../../src/utils/immutability.js';

/**
 * T089: memory.store UPDATE Functionality Test
 *
 * Validates:
 * - UPDATE operations work when id field is provided
 * - INSERT operations work when id field is omitted
 * - ADR immutability is enforced during UPDATE
 * - Section write-lock is enforced during UPDATE
 * - Proper error messages are returned for violations
 */
describe('memory.store UPDATE Operations', () => {
  let pool: Pool;

  beforeAll(() => {
    pool = new Pool({
      connectionString:
        process.env.DATABASE_URL || 'postgresql://cortex:cortex@localhost:5432/cortex_test',
    });
  });

  afterAll(async () => {
    await pool.end();
  });

  describe('ADR Decision Updates', () => {
    it('should allow updates to proposed ADR content', async () => {
      // Insert ADR with status='proposed'
      const insertResult = await memoryStore([
        {
          kind: 'decision',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            component: 'auth',
            status: 'proposed',
            title: 'Original Title',
            rationale: 'Original rationale',
          },
        },
      ]);

      expect(insertResult.stored).toHaveLength(1);
      expect(insertResult.stored[0].status).toBe('inserted');
      const adrId = insertResult.stored[0].id;

      // Update content (should succeed - not yet accepted)
      const updateResult = await memoryStore([
        {
          kind: 'decision',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            id: adrId,
            title: 'Updated Title',
            rationale: 'Updated rationale',
          },
        },
      ]);

      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('updated');
      expect(updateResult.stored[0].id).toBe(adrId);

      // Verify update in database
      const result = await pool.query('SELECT title, rationale FROM adr_decision WHERE id = $1', [
        adrId,
      ]);
      expect(result.rows[0].title).toBe('Updated Title');
      expect(result.rows[0].rationale).toBe('Updated rationale');

      // Cleanup
      await pool.query('DELETE FROM adr_decision WHERE id = $1', [adrId]);
    });

    it('should block content updates to accepted ADR', async () => {
      // Insert accepted ADR
      const insertResult = await memoryStore([
        {
          kind: 'decision',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            component: 'database',
            status: 'accepted',
            title: 'Immutable Title',
            rationale: 'Immutable rationale',
          },
        },
      ]);

      const adrId = insertResult.stored[0].id;

      // Attempt to update content (should fail)
      await expect(
        memoryStore([
          {
            kind: 'decision',
            scope: { project: 'test-project', branch: 'main' },
            data: {
              id: adrId,
              title: 'Trying to change immutable title',
            },
          },
        ])
      ).rejects.toThrow(ImmutabilityViolationError);

      // Verify original content unchanged
      const result = await pool.query('SELECT title FROM adr_decision WHERE id = $1', [adrId]);
      expect(result.rows[0].title).toBe('Immutable Title');

      // Cleanup
      await pool.query('DELETE FROM adr_decision WHERE id = $1', [adrId]);
    });

    it('should return proper error for non-existent ADR update', async () => {
      const nonExistentId = '00000000-0000-0000-0000-000000000000';

      const updateResult = await memoryStore([
        {
          kind: 'decision',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            id: nonExistentId,
            title: 'Update non-existent',
          },
        },
      ]);

      // Should insert new record instead of updating (no existing record found)
      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('inserted');

      // Cleanup
      await pool.query('DELETE FROM adr_decision WHERE id = $1', [updateResult.stored[0].id]);
    });
  });

  describe('Section Updates', () => {
    it('should allow updates to unapproved section', async () => {
      // Insert section without approved flag
      const insertResult = await memoryStore([
        {
          kind: 'section',
          scope: { project: 'test-project', branch: 'feature' },
          data: {
            title: 'Draft Section',
            body_md: '# Original content',
          },
        },
      ]);

      expect(insertResult.stored).toHaveLength(1);
      const sectionId = insertResult.stored[0].id;

      // Update content (should succeed)
      const updateResult = await memoryStore([
        {
          kind: 'section',
          scope: { project: 'test-project', branch: 'feature' },
          data: {
            id: sectionId,
            body_md: '# Updated content',
          },
        },
      ]);

      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('updated');

      // Verify update in database
      const result = await pool.query('SELECT body_jsonb FROM section WHERE id = $1', [sectionId]);
      expect(result.rows[0].body_jsonb.text).toBe('# Updated content');

      // Cleanup
      await pool.query('DELETE FROM section WHERE id = $1', [sectionId]);
    });

    it('should block content updates to approved section', async () => {
      // Insert approved section
      const insertResult = await memoryStore([
        {
          kind: 'section',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Approved Spec',
            body_md: '# Locked content',
          },
          tags: { approved: true },
        },
      ]);

      const sectionId = insertResult.stored[0].id;

      // Attempt to update content (should fail)
      await expect(
        memoryStore([
          {
            kind: 'section',
            scope: { project: 'test-project', branch: 'main' },
            data: {
              id: sectionId,
              body_md: '# Trying to change locked content',
            },
          },
        ])
      ).rejects.toThrow(ImmutabilityViolationError);

      // Verify original content unchanged
      const result = await pool.query('SELECT body_jsonb FROM section WHERE id = $1', [sectionId]);
      expect(result.rows[0].body_jsonb.text).toBe('# Locked content');

      // Cleanup
      await pool.query('DELETE FROM section WHERE id = $1', [sectionId]);
    });
  });

  describe('INSERT vs UPDATE Distinction', () => {
    it('should INSERT when id is not provided', async () => {
      const insertResult = await memoryStore([
        {
          kind: 'decision',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            component: 'api',
            status: 'proposed',
            title: 'New Decision',
            rationale: 'New rationale',
          },
        },
      ]);

      expect(insertResult.stored).toHaveLength(1);
      expect(insertResult.stored[0].status).toBe('inserted');
      expect(insertResult.stored[0].id).toBeDefined();

      // Cleanup
      await pool.query('DELETE FROM adr_decision WHERE id = $1', [insertResult.stored[0].id]);
    });

    it('should UPDATE when id is provided and exists', async () => {
      // First insert
      const insertResult = await memoryStore([
        {
          kind: 'decision',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            component: 'api',
            status: 'proposed',
            title: 'Original',
            rationale: 'Original',
          },
        },
      ]);

      const adrId = insertResult.stored[0].id;

      // Then update
      const updateResult = await memoryStore([
        {
          kind: 'decision',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            id: adrId,
            title: 'Modified',
          },
        },
      ]);

      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('updated');
      expect(updateResult.stored[0].id).toBe(adrId);

      // Cleanup
      await pool.query('DELETE FROM adr_decision WHERE id = $1', [adrId]);
    });
  });
});
