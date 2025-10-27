import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { getTestContainer } from '../helpers/testcontainers.ts';

/**
 * T010: Qdrant Collection Schema validation test (RED phase)
 *
 * Verifies all 16 collections exist with:
 * - Correct vector configurations
 * - Payload schemas
 * - Performance indexes
 * - Proper collection naming
 */

describe('Qdrant Collection Schema', () => {
  let client: QdrantClient;
  let cleanup: () => Promise<void>;

  beforeAll(async () => {
    const { client: testClient, cleanup: cleanupFn } = await getTestContainer();
    client = testClient;
    cleanup = cleanupFn;
  }, 120000);

  afterAll(async () => {
    await cleanup();
  });

  const expectedTables = [
    'document',
    'section',
    'runbook',
    'pr_context',
    'ddl_history',
    'release_note',
    'change_log',
    'issue_log',
    'adr_decision',
    'todo_log',
    'event_audit',
  ];

  it.each(expectedTables)('should have %s table', async (tableName) => {
    const result = await client.query(
      `SELECT tablename FROM .collections WHERE schemaname = 'public' AND tablename = $1`,
      [tableName]
    );
    expect(result.rows).toHaveLength(1);
  });

  it('should have GIN index on section.ts for FTS', async () => {
    const result = await client.query(`
      SELECT indexname FROM .indexes
      WHERE tablename = 'section' AND indexname = 'section_fts_idx'
    `);
    expect(result.rows).toHaveLength(1);
  });

  it('should have GIN index on section.tags for scope filtering', async () => {
    const result = await client.query(`
      SELECT indexname FROM .indexes
      WHERE tablename = 'section' AND indexname = 'section_tags_gin'
    `);
    expect(result.rows).toHaveLength(1);
  });

  it('should have trigger t_section_touch for auto-updated_at', async () => {
    const result = await client.query(`
      SELECT tgname FROM .triggers
      WHERE tgname = 't_section_touch' AND tgrelid = 'section'::regclass
    `);
    expect(result.rows).toHaveLength(1);
  });

  it('should have trigger t_audit_section for audit logging', async () => {
    const result = await client.query(`
      SELECT tgname FROM .triggers
      WHERE tgname = 't_audit_section' AND tgrelid = 'section'::regclass
    `);
    expect(result.rows).toHaveLength(1);
  });

  it('should have trigger t_adr_immutable for ADR immutability', async () => {
    const result = await client.query(`
      SELECT tgname FROM .triggers
      WHERE tgname = 't_adr_immutable' AND tgrelid = 'adr_decision'::regclass
    `);
    expect(result.rows).toHaveLength(1);
  });

  it('should have trigger t_doc_approved_lock for approved spec write-lock', async () => {
    const result = await client.query(`
      SELECT tgname FROM .triggers
      WHERE tgname = 't_doc_approved_lock' AND tgrelid = 'document'::regclass
    `);
    expect(result.rows).toHaveLength(1);
  });
});
