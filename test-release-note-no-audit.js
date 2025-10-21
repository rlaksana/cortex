import('./dist/services/knowledge/release_note.js').then(({ storeReleaseNote }) => {
  import('./dist/db/pool.js').then(async ({ dbPool }) => {
    await dbPool.initialize();

    const releaseNoteData = {
      version: '1.0.0',
      release_date: new Date().toISOString(),
      summary: 'Initial release with core knowledge management features',
      new_features: ['Knowledge storage system', 'Full-text search capabilities', 'Memory validation framework'],
      bug_fixes: ['Fixed connection pooling issues', 'Resolved validation errors', 'Corrected field mapping problems'],
      breaking_changes: [],
      deprecations: []
    };

    console.log('🔧 Testing Release Note DIRECT (no audit logging)...');

    try {
      const id = await storeReleaseNote(dbPool, releaseNoteData, { project: 'test-project' });
      console.log('✅ Release Note: SUCCESS');
      console.log(`   ID: ${id}`);
      console.log('   Status: WORKING');
    } catch (error) {
      console.log('❌ Release Note: FAILED');
      console.log('Error:', error.message);
    } finally {
      await dbPool.shutdown();
    }
  }).catch(console.error);
}).catch(console.error);