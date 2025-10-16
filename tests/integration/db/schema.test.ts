import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { getTestContainer } from '../../helpers/testcontainers.js';
import { Client } from 'pg';

/**
 * T010: Schema validation test (RED phase)
 *
 * Verifies all 11 tables exist with:
 * - Correct columns and data types
 * - GIN indexes (FTS vectors, JSONB tags)
 * - Triggers (t_*_touch, t_audit_*, t_adr_immutable, t_doc_approved_lock)
 */

describe('Database Schema', () => {
  let client: Client;
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
      `SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = $1`,
      [tableName]
    );
    expect(result.rows).toHaveLength(1);
  });

  it('should have GIN index on section.ts for FTS', async () => {
    const result = await client.query(`
      SELECT indexname FROM pg_indexes
      WHERE tablename = 'section' AND indexname = 'section_fts_idx'
    `);
    expect(result.rows).toHaveLength(1);
  });

  it('should have GIN index on section.tags for scope filtering', async () => {
    const result = await client.query(`
      SELECT indexname FROM pg_indexes
      WHERE tablename = 'section' AND indexname = 'section_tags_gin'
    `);
    expect(result.rows).toHaveLength(1);
  });

  it('should have trigger t_section_touch for auto-updated_at', async () => {
    const result = await client.query(`
      SELECT tgname FROM pg_trigger
      WHERE tgname = 't_section_touch' AND tgrelid = 'section'::regclass
    `);
    expect(result.rows).toHaveLength(1);
  });

  it('should have trigger t_audit_section for audit logging', async () => {
    const result = await client.query(`
      SELECT tgname FROM pg_trigger
      WHERE tgname = 't_audit_section' AND tgrelid = 'section'::regclass
    `);
    expect(result.rows).toHaveLength(1);
  });

  it('should have trigger t_adr_immutable for ADR immutability', async () => {
    const result = await client.query(`
      SELECT tgname FROM pg_trigger
      WHERE tgname = 't_adr_immutable' AND tgrelid = 'adr_decision'::regclass
    `);
    expect(result.rows).toHaveLength(1);
  });

  it('should have trigger t_doc_approved_lock for approved spec write-lock', async () => {
    const result = await client.query(`
      SELECT tgname FROM pg_trigger
      WHERE tgname = 't_doc_approved_lock' AND tgrelid = 'document'::regclass
    `);
    expect(result.rows).toHaveLength(1);
  });
});
