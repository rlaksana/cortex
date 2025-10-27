import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { getTestContainer } from '../helpers/testcontainers.ts';
// PostgreSQL import removed - now using Qdrant;
import { seedDatabase } from '../scripts/seed.ts';

/**
 * T011: Seed data test (RED phase)
 *
 * Verifies seed script inserts:
 * - 1 document (title="Getting Started Guide", type="guide")
 * - 3 sections (chunked with FTS vectors)
 * - 1 ADR (status="accepted")
 * - 1 issue (status="open")
 * - 1 todo (status="open")
 * All with scope {project: "cortex", branch: "main"}
 */

describe('Seed Data', () => {
  let client: Client;
  let cleanup: () => Promise<void>;

  beforeAll(async () => {
    const { client: testClient, cleanup: cleanupFn } = await getTestContainer();
    client = testClient;
    cleanup = cleanupFn;

    // Run seed script
    await seedDatabase(client);
  }, 120000);

  afterAll(async () => {
    await cleanup();
  });

  it('should insert 1 document', async () => {
    const result = await client.query(`SELECT COUNT(*) as count FROM document`);
    expect(parseInt(result.rows[0].count)).toBe(1);
  });

  it('should have document with correct title and type', async () => {
    const result = await client.query(`
      SELECT title, type FROM document WHERE title = 'Getting Started Guide'
    `);
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0].type).toBe('guide');
  });

  it('should insert 3 sections', async () => {
    const result = await client.query(`SELECT COUNT(*) as count FROM section`);
    expect(parseInt(result.rows[0].count)).toBe(3);
  });

  it('should have sections with FTS vectors', async () => {
    const result = await client.query(`
      SELECT id FROM section WHERE ts IS NOT NULL
    `);
    expect(result.rows).toHaveLength(3);
  });

  it('should insert 1 ADR with status accepted', async () => {
    const result = await client.query(`
      SELECT COUNT(*) as count FROM adr_decision WHERE status = 'accepted'
    `);
    expect(parseInt(result.rows[0].count)).toBe(1);
  });

  it('should insert 1 issue with status open', async () => {
    const result = await client.query(`
      SELECT COUNT(*) as count FROM issue_log WHERE status = 'open'
    `);
    expect(parseInt(result.rows[0].count)).toBe(1);
  });

  it('should insert 1 todo with status open', async () => {
    const result = await client.query(`
      SELECT COUNT(*) as count FROM todo_log WHERE status = 'open'
    `);
    expect(parseInt(result.rows[0].count)).toBe(1);
  });

  it('should have all items with correct scope', async () => {
    const tables = ['section', 'adr_decision', 'issue_log', 'todo_log'];

    for (const table of tables) {
      const result = await client.query(`
        SELECT tags->>'project' as project, tags->>'branch' as branch
        FROM ${table} LIMIT 1
      `);
      expect(result.rows[0].project).toBe('cortex');
      expect(result.rows[0].branch).toBe('main');
    }
  });
});
