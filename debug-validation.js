import('./dist/services/memory-store.js')
  .then(({ memoryStore }) => {
    // Test just ONE item at a time to identify specific validation issues
    const testSection = {
      kind: 'section',
      scope: { project: 'test-project' }, // Section MUST have scope
      data: {
        title: 'Test Section - Valid Content',
        heading: 'Test Heading',
        body_md: '# Test Content\\n\\nThis is valid markdown content for testing.',
      },
    };

    console.log('Testing single section item with detailed logging...');
    console.log('Test item:', JSON.stringify(testSection, null, 2));

    memoryStore([testSection])
      .then((result) => {
        console.log('\\n=== SECTION TEST RESULT ===');
        console.log('Stored:', result.stored.length);
        console.log('Errors:', result.errors.length);

        if (result.errors.length > 0) {
          console.log('\\n🔍 Detailed Error Analysis:');
          result.errors.forEach((error, i) => {
            console.log(`Error ${i + 1}:`);
            console.log(`  Code: ${error.error_code}`);
            console.log(`  Message: ${error.message}`);
            console.log(`  Field: ${error.field || 'N/A'}`);
            console.log(`  Index: ${error.index}`);
          });
        }

        if (result.stored.length > 0) {
          console.log('\\n✅ SUCCESS! Section stored successfully:');
          console.log('  ID:', result.stored[0].id);
          console.log('  Kind:', result.stored[0].kind);
          console.log('  Status:', result.stored[0].status);
          console.log('  Created:', result.stored[0].created_at);
        }
      })
      .catch((error) => {
        console.error('❌ Test failed:', error.message);
        console.error('Stack:', error.stack);
      });
  })
  .catch(console.error);
