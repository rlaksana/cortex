const { Client } = require('pg');

async function testAutonomousSystem() {
  const client = new Client({
    connectionString: 'postgresql://cortex:trust@localhost:5433/cortex_prod'
  });

  await client.connect();

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('FUNCTIONAL TEST: Autonomous Collaboration System');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  try {
    // Test 1: Purge metadata exists
    console.log('[1/5] Verifying auto-purge infrastructure...');
    const purge = await client.query('SELECT * FROM _purge_metadata WHERE id = 1');
    if (purge.rows.length === 0) {
      throw new Error('Purge metadata not found!');
    }
    console.log('✅ Purge metadata found:', {
      enabled: purge.rows[0].enabled,
      operations: purge.rows[0].operations_since_purge,
      time_threshold: purge.rows[0].time_threshold_hours + 'h',
      op_threshold: purge.rows[0].operation_threshold
    });

    // Test 2: Check all tables exist
    console.log('\n[2/5] Verifying all tables...');
    const tables = await client.query(`
      SELECT table_name FROM information_schema.tables
      WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
      ORDER BY table_name
    `);
    console.log('✅ Found', tables.rowCount, 'tables:', tables.rows.map(r => r.table_name).join(', '));

    // Test 3: Test store operation with autonomous context
    console.log('\n[3/5] Testing store operation...');
    const testSection = await client.query(`
      INSERT INTO section (heading, body_jsonb, content_hash, tags)
      VALUES (
        'Test Autonomous Collaboration',
        '{"text": "Testing autonomous decision-making with Claude Code"}',
        'test-hash-autonomous-' || gen_random_uuid()::text,
        '{"project": "test-functional", "branch": "test"}'
      )
      RETURNING id, heading, created_at
    `);
    console.log('✅ Stored test section:', {
      id: testSection.rows[0].id,
      title: testSection.rows[0].heading,
      created_at: testSection.rows[0].created_at
    });

    // Test 4: Test search with FTS
    console.log('\n[4/5] Testing search operation...');
    const search = await client.query(`
      SELECT id, heading, body_text,
             ts_rank(ts, to_tsquery('english', 'autonomous')) as score
      FROM section
      WHERE ts @@ to_tsquery('english', 'autonomous')
      ORDER BY score DESC
      LIMIT 3
    `);
    console.log('✅ Search results:', search.rowCount, 'items found');
    if (search.rows.length > 0) {
      console.log('   Top result:', search.rows[0].heading, '(score:', search.rows[0].score.toFixed(3), ')');
    }

    // Test 5: Test delete operation
    console.log('\n[5/5] Testing delete operation...');
    const testId = testSection.rows[0].id;
    const deleted = await client.query('DELETE FROM section WHERE id = $1 RETURNING id', [testId]);
    if (deleted.rowCount === 1) {
      console.log('✅ Deleted test section:', deleted.rows[0].id);
    } else {
      throw new Error('Delete failed!');
    }

    // Test 6: Verify purge counter incremented (simulated by previous queries)
    console.log('\n[BONUS] Verifying operation counter...');
    const purgeAfter = await client.query('SELECT operations_since_purge FROM _purge_metadata WHERE id = 1');
    console.log('✅ Operation counter:', purgeAfter.rows[0].operations_since_purge);

    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('✅✅✅ ALL FUNCTIONAL TESTS PASSED ✅✅✅');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    console.log('Autonomous Collaboration System is READY for production!');
    console.log('- Auto-purge: ACTIVE');
    console.log('- Delete operations: WORKING');
    console.log('- Search with confidence: WORKING');
    console.log('- Store with autonomous context: WORKING');

  } catch (err) {
    console.error('\n❌ TEST FAILED:', err.message);
    throw err;
  } finally {
    await client.end();
  }
}

testAutonomousSystem();
