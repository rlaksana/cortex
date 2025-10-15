/**
 * E2E tests for complete autonomous collaboration scenarios
 * Simulates Claude Code making autonomous decisions based on tool responses
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from 'pg';
import { memoryStore } from '../../src/services/memory-store.js';
import { memoryFind } from '../../src/services/memory-find.js';
import { loadEnv } from '../../src/config/env.js';

loadEnv();

describe('E2E: Autonomous Claude Code Scenarios', () => {
  let client: Client;
  const testScope = { project: 'e2e-autonomous', branch: 'main' };

  beforeAll(async () => {
    client = new Client({ connectionString: process.env.DATABASE_URL });
    await client.connect();

    // Clean slate
    await client.query(`DELETE FROM section WHERE (tags->>'project') = 'e2e-autonomous'`);
    await client.query(`DELETE FROM adr_decision WHERE (tags->>'project') = 'e2e-autonomous'`);
  });

  afterAll(async () => {
    await client.query(`DELETE FROM section WHERE (tags->>'project') = 'e2e-autonomous'`);
    await client.query(`DELETE FROM adr_decision WHERE (tags->>'project') = 'e2e-autonomous'`);
    await client.end();
  });

  it('Scenario: User shares information, Claude saves autonomously', async () => {
    // User: "We use PostgreSQL 18 for the database"
    // Claude Code autonomous flow:

    // Step 1: Search first
    const searchResult = await memoryFind({
      query: 'PostgreSQL database',
      scope: testScope,
    });

    // Step 2: No results, so CREATE
    expect(searchResult.hits).toHaveLength(0);

    const storeResult = await memoryStore([
      {
        kind: 'section',
        scope: testScope,
        data: {
          title: 'Database Technology',
          body_md: 'Using PostgreSQL 18 for persistence',
        },
      },
    ]);

    // Step 3: Check autonomous context
    expect(storeResult.autonomous_context.action_performed).toBe('created');
    const userMessage = storeResult.autonomous_context.user_message_suggestion;
    expect(userMessage).toContain('Saved');

    // Step 4: Claude informs user (NO prompts!)
    console.log(userMessage); // "✓ Saved section: ..."
  });

  it('Scenario: User corrects information, Claude updates autonomously', async () => {
    // Setup: Store initial (wrong) information
    const initial = await memoryStore([
      {
        kind: 'section',
        scope: testScope,
        data: {
          title: 'API Framework',
          body_md: 'Using Express.js for the API',
        },
      },
    ]);

    const oldId = initial.stored[0].id;

    // User: "Actually, we use Fastify not Express"
    // Claude Code autonomous flow:

    // Step 1: Detect correction keywords
    const userIntent = 'correction'; // Detected from "actually"

    // Step 2: Search for existing info
    const existing = await memoryFind({
      query: 'API framework',
      scope: testScope,
    });

    expect(existing.hits).toHaveLength(1);

    // Step 3: Delete old + Create new (autonomous decision)
    await memoryStore([
      {
        operation: 'delete',
        kind: 'section',
        id: existing.hits[0].id,
      },
    ]);

    const newResult = await memoryStore([
      {
        kind: 'section',
        scope: testScope,
        data: {
          title: 'API Framework',
          body_md: 'Using Fastify for the API',
        },
      },
    ]);

    // Step 4: Verify and inform user
    expect(newResult.autonomous_context.action_performed).toBe('created');
    console.log('✓ Corrected API framework (Express → Fastify)');

    // Verify old is gone
    const verify = await memoryFind({
      query: 'Express',
      scope: testScope,
    });

    expect(verify.hits.filter((h) => h.title === 'API Framework')).toHaveLength(0);
  });

  it('Scenario: Duplicate prevention with autonomous skip', async () => {
    // User shares same info twice
    // Claude Code handles autonomously

    const first = await memoryStore([
      {
        kind: 'decision',
        scope: testScope,
        data: {
          component: 'auth',
          status: 'accepted',
          title: 'Use OAuth 2.0',
          rationale: 'Industry standard, well-supported',
          alternatives_considered: ['Basic Auth', 'JWT only'],
        },
      },
    ]);

    expect(first.autonomous_context.action_performed).toBe('created');

    // User accidentally repeats same info
    const duplicate = await memoryStore([
      {
        kind: 'decision',
        scope: testScope,
        data: {
          component: 'auth',
          status: 'accepted',
          title: 'Use OAuth 2.0',
          rationale: 'Industry standard, well-supported',
          alternatives_considered: ['Basic Auth', 'JWT only'],
        },
      },
    ]);

    // Autonomous handling: Skip duplicate
    expect(duplicate.stored[0].status).toBe('skipped_dedupe');
    expect(duplicate.autonomous_context.action_performed).toBe('skipped');
    expect(duplicate.autonomous_context.duplicates_found).toBeGreaterThan(0);

    // Claude informs user (no prompt!)
    console.log(duplicate.autonomous_context.user_message_suggestion); // "⊘ Already in memory"
  });

  it('Scenario: Low confidence search triggers autonomous retry', async () => {
    // Store test data
    await memoryStore([
      {
        kind: 'section',
        scope: testScope,
        data: {
          title: 'Security Best Practices',
          body_md: 'Use HTTPS, validate inputs, sanitize outputs',
        },
      },
    ]);

    // User: "Find security stuff" (vague query)
    // Claude Code autonomous flow:

    // Step 1: Initial search
    let searchResult = await memoryFind({
      query: 'security stuff',
      scope: testScope,
      mode: 'auto',
    });

    // Step 2: Check confidence
    const confidence = searchResult.autonomous_metadata.confidence;

    // Step 3: If low, retry autonomously
    if (confidence === 'low') {
      searchResult = await memoryFind({
        query: 'security best practices',
        scope: testScope,
        mode: 'deep',
      });
    }

    // Step 4: Use results, inform user
    expect(searchResult.hits.length).toBeGreaterThan(0);
    console.log(searchResult.autonomous_metadata.user_message_suggestion);
  });

  it('Scenario: Auto-purge runs transparently', async () => {
    // Simulate operations counter exceeding threshold
    // (In real scenario, this happens after 1000 operations)

    // Store operation increments counter
    const storeResult = await memoryStore([
      {
        kind: 'section',
        scope: testScope,
        data: {
          title: 'Test Auto-Purge',
          body_md: 'This tests purge integration',
        },
      },
    ]);

    // Purge metadata should have incremented
    const meta = await client.query(
      'SELECT operations_since_purge FROM _purge_metadata WHERE id = 1'
    );
    expect(meta.rows[0].operations_since_purge).toBeGreaterThan(0);

    // User should NOT be aware purge is happening
    // autonomous_context doesn't mention purge (seamless)
    expect(storeResult.autonomous_context.user_message_suggestion).not.toContain('purge');
  });
});
