import { Client } from 'pg';

export async function seedDatabase(client: Client): Promise<void> {
  const docId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';
  const scope = { project: 'cortex-memory', branch: 'main' };

  await client.query(`
    INSERT INTO document (id, type, title, tags)
    VALUES ($1, 'guide', 'Getting Started Guide', $2)
  `, [docId, JSON.stringify(scope)]);

  const sections = [
    { heading: 'Installation', body: 'Run npm install to get started with Cortex Memory MCP.' },
    { heading: 'Configuration', body: 'Set DATABASE_URL in your .env file pointing to PostgreSQL 18+.' },
    { heading: 'Usage', body: 'Use memory.store to persist knowledge and memory.find to retrieve it.' }
  ];

  for (const s of sections) {
    const hash = require('crypto').createHash('sha256').update(s.body).digest('hex');
    await client.query(`
      INSERT INTO section (document_id, heading, body_jsonb, content_hash, tags)
      VALUES ($1, $2, $3, $4, $5)
    `, [docId, s.heading, JSON.stringify({ text: s.body }), hash, JSON.stringify(scope)]);
  }

  await client.query(`
    INSERT INTO adr_decision (component, status, title, rationale, tags)
    VALUES ('database', 'accepted', 'Use PostgreSQL 18 as SoT', 'Single source of truth with FTS support', $1)
  `, [JSON.stringify(scope)]);

  await client.query(`
    INSERT INTO issue_log (tracker, external_id, title, status, tags)
    VALUES ('github', 'CORT-001', 'Setup CI pipeline', 'open', $1)
  `, [JSON.stringify(scope)]);

  await client.query(`
    INSERT INTO todo_log (scope, todo_type, text, status, tags)
    VALUES ('development', 'task', 'Write E2E tests', 'open', $1)
  `, [JSON.stringify(scope)]);
}

if (require.main === module) {
  const { loadEnv } = require('../src/config/env.js');
  const env = loadEnv();
  const client = new Client({ connectionString: env.DATABASE_URL });
  client.connect().then(() => seedDatabase(client)).then(() => client.end());
}
