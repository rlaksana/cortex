import('./dist/services/memory-store.js').then(({ memoryStore }) => {

  // Test Release Note dengan format yang benar
  const releaseNoteTest = {
    kind: 'release_note',
    scope: { project: 'test-project' },
    data: {
      version: '1.0.0',
      release_date: new Date().toISOString(),
      summary: 'Initial release with core knowledge management features',
      new_features: 'Knowledge storage system, Full-text search capabilities, Memory validation framework',
      bug_fixes: 'Fixed connection pooling issues, Resolved validation errors, Corrected field mapping problems'
    }
  };

  console.log('🔧 Testing Release Note with corrected array field format...');

  memoryStore([releaseNoteTest]).then(result => {
    console.log('=== RELEASE NOTE TEST RESULT ===');

    if (result.stored.length > 0 && result.errors.length === 0) {
      console.log('✅ Release Note: SUCCESS');
      console.log(`   ID: ${result.stored[0].id}`);
      console.log('   Status: WORKING');
    } else {
      console.log('❌ Release Note: FAILED');
      console.log('Error details:', result.errors);
    }
  }).catch(error => {
    console.error('❌ Test failed:', error.message);
  });

}).catch(console.error);