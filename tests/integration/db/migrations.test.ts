import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { PostgreSqlContainer, StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { Client } from 'pg';

/**
 * T009: Migration smoke test (RED phase)
 *
 * Verifies:
 * - Migrations apply cleanly without errors
 * - PostgreSQL extensions exist (pgcrypto, pg_trgm)
 * - Migration history is recorded in ddl_history table
 */

describe('Database Migrations', () => {
  let container: StartedPostgreSqlContainer;
  let client: Client;

  beforeAll(async () => {
    // Start PostgreSQL 18 container
    container = await new PostgreSqlContainer('postgres:18-alpine')
      .withDatabase('cortex_test')
      .withUsername('test')
      .withPassword('test')
      .start();

    client = new Client({
      connectionString: container.getConnectionString(),
    });
    await client.connect();
  }, 120000);

  afterAll(async () => {
    await client?.end();
    await container?.stop();
  });

  it('should apply all migrations successfully', async () => {
    // This will fail until T013-T015 are implemented
    const { runMigrations } = await import('../../../src/db/migrate.js');

    await expect(runMigrations(container.getConnectionString())).resolves.not.toThrow();
  });

  it('should have pgcrypto extension installed', async () => {
    const result = await client.query(
      `SELECT extname FROM pg_extension WHERE extname = 'pgcrypto'`
    );
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0].extname).toBe('pgcrypto');
  });

  it('should have pg_trgm extension installed', async () => {
    const result = await client.query(`SELECT extname FROM pg_extension WHERE extname = 'pg_trgm'`);
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0].extname).toBe('pg_trgm');
  });

  it('should record migration history in ddl_history table', async () => {
    const result = await client.query(
      `SELECT COUNT(*) as count FROM ddl_history WHERE migration_id LIKE '000%'`
    );
    expect(parseInt(result.rows[0].count)).toBeGreaterThan(0);
  });
});
