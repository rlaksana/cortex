import('./dist/services/memory-store.js')
  .then(async ({ memoryStore }) => {
    const crypto = await import('crypto');

    // Generate proper SHA-256 checksum
    const ddlText = 'CREATE TABLE knowledge_items (id UUID PRIMARY KEY DEFAULT gen_random_uuid());';
    const checksum = crypto.createHash('sha256').update(ddlText).digest('hex');

    // Test DDL dengan proper checksum
    const ddlTest = {
      kind: 'ddl',
      scope: { project: 'test-project' },
      data: {
        migration_id: '001_initial_schema',
        ddl_text: ddlText,
        checksum: checksum, // 64 karakter SHA-256
        description: 'Initial database schema for knowledge items',
      },
    };

    console.log('🔧 Testing DDL with proper SHA-256 checksum...');
    console.log(`Checksum length: ${checksum.length} characters`);

    memoryStore([ddlTest])
      .then((result) => {
        console.log('=== DDL TEST RESULT ===');

        if (result.stored.length > 0 && result.errors.length === 0) {
          console.log('✅ DDL: SUCCESS');
          console.log(`   ID: ${result.stored[0].id}`);
          console.log('   Status: WORKING');
        } else {
          console.log('❌ DDL: FAILED');
          console.log('Error details:', result.errors);
        }
      })
      .catch((error) => {
        console.error('❌ Test failed:', error.message);
      });
  })
  .catch(console.error);
