import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';
import { Client } from 'pg';
import { createHash } from 'crypto';
import { logger } from '../utils/logger.js';

export async function runMigrations(connectionString: string): Promise<void> {
  const client = new Client({ connectionString });
  await client.connect();

  try {
    // Create ddl_history table if it doesn't exist
    await client.query(`
      CREATE TABLE IF NOT EXISTS ddl_history (
        id SERIAL PRIMARY KEY,
        migration_id TEXT NOT NULL UNIQUE,
        ddl_text TEXT NOT NULL,
        checksum TEXT NOT NULL,
        description TEXT,
        applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `);

    const migrationsDir = join(process.cwd(), 'migrations');
    const files = readdirSync(migrationsDir)
      .filter((f) => f.endsWith('.sql'))
      .sort();

    for (const file of files) {
      const migrationId = file.replace('.sql', '');
      const filePath = join(migrationsDir, file);
      const ddlText = readFileSync(filePath, 'utf8');
      const checksum = createHash('sha256').update(ddlText).digest('hex');

      const existing = await client.query(
        'SELECT checksum FROM ddl_history WHERE migration_id = $1',
        [migrationId]
      );

      if (existing.rows.length === 0) {
        await client.query(ddlText);
        await client.query(
          'INSERT INTO ddl_history (migration_id, ddl_text, checksum) VALUES ($1, $2, $3)',
          [migrationId, ddlText, checksum]
        );
        logger.info({ migration_id: migrationId }, 'Migration applied');
      } else if (existing.rows[0].checksum !== checksum) {
        throw new Error(`Migration ${migrationId} checksum mismatch`);
      }
    }
  } finally {
    await client.end();
  }
}

// Main entry point when run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    console.error('DATABASE_URL environment variable is required');
    process.exit(1);
  }

  runMigrations(connectionString)
    .then(() => {
      logger.info('All migrations completed successfully');
      process.exit(0);
    })
    .catch((err) => {
      logger.error({ err }, 'Migration failed');
      process.exit(1);
    });
}
