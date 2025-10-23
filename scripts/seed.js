#!/usr/bin/env node

import { Client } from 'pg';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import crypto from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Seed the database with sample data for testing and development
 */
export async function seedDatabase(client) {
  const docId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';
  const scope = { project: 'cortex', branch: 'main' };

  try {
    await client.query(`
      INSERT INTO document (id, type, title, tags)
      VALUES ($1, 'guide', 'Getting Started Guide', $2)
      ON CONFLICT (id) DO NOTHING
    `, [docId, JSON.stringify(scope)]);

    const sections = [
      { heading: 'Installation', body: 'Run npm install to get started with Cortex MCP.' },
      { heading: 'Configuration', body: 'Set DATABASE_URL in your .env file pointing to PostgreSQL 15+.' },
      { heading: 'Usage', body: 'Use memory.store to persist knowledge and memory.find to retrieve it.' }
    ];

    for (const s of sections) {
      const hash = crypto.createHash('sha256').update(s.body).digest('hex');
      await client.query(`
        INSERT INTO section (document_id, heading, body_jsonb, content_hash, tags)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (document_id, heading) DO NOTHING
      `, [docId, s.heading, JSON.stringify({ text: s.body }), hash, JSON.stringify(scope)]);
    }

    await client.query(`
      INSERT INTO adr_decision (component, status, title, rationale, tags)
      VALUES ('database', 'accepted', 'Use PostgreSQL 15 as SoT', 'Single source of truth with FTS support', $1)
      ON CONFLICT (component, title) DO NOTHING
    `, [JSON.stringify(scope)]);

    await client.query(`
      INSERT INTO issue_log (tracker, external_id, title, status, tags)
      VALUES ('github', 'CORT-001', 'Setup CI pipeline', 'closed', $1)
      ON CONFLICT (tracker, external_id) DO NOTHING
    `, [JSON.stringify(scope)]);

    await client.query(`
      INSERT INTO todo_log (scope, todo_type, text, status, tags)
      VALUES ('development', 'task', 'Write E2E tests', 'completed', $1)
      ON CONFLICT (scope, text) DO NOTHING
    `, [JSON.stringify(scope)]);

    console.log('✅ Database seeded successfully');
  } catch (error) {
    console.error('❌ Error seeding database:', error);
    throw error;
  }
}

/**
 * Main execution function
 */
async function main() {
  let client;

  try {
    // Load environment variables
    const envFile = join(__dirname, '..', '.env');

    // Get DATABASE_URL from environment or use default
    const databaseUrl = process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/cortex_test';

    console.log('🌱 Seeding database...');

    client = new Client({ connectionString: databaseUrl });
    await client.connect();

    await seedDatabase(client);

    console.log('🎉 Database seeding completed successfully');
  } catch (error) {
    console.error('💥 Database seeding failed:', error.message);
    process.exit(1);
  } finally {
    if (client) {
      await client.end();
    }
  }
}

// Run if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}