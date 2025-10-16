import { PostgreSqlContainer, StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { Client } from 'pg';
import { runMigrations } from '../../src/db/migrate.js';
import { seedDatabase } from '../../scripts/seed.js';

export async function getTestContainer(): Promise<{
  client: Client;
  cleanup: () => Promise<void>;
}> {
  const container = await new PostgreSqlContainer('postgres:18-alpine')
    .withDatabase('cortex_test')
    .withUsername('test')
    .withPassword('test')
    .start();

  const connectionString = container.getConnectionString();
  await runMigrations(connectionString);

  const client = new Client({ connectionString });
  await client.connect();
  await seedDatabase(client);

  return {
    client,
    cleanup: async () => {
      await client.end();
      await container.stop();
    },
  };
}
