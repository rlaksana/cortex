import('./dist/services/memory-store.js').then(({ memoryStore }) => {

  const tests = [
    {
      name: 'Section',
      item: {
        kind: 'section',
        scope: { project: 'test-project' },
        data: {
          title: 'Test Section Documentation',
          heading: 'Technical Specification',
          body_md: '# Test Content\\n\\nThis is valid markdown content.',
        }
      }
    },
    {
      name: 'Decision',
      item: {
        kind: 'decision',
        scope: { project: 'test-project' },
        data: {
          component: 'Architecture',
          title: 'Database Technology Choice',
          rationale: 'PostgreSQL provides superior ACID compliance, advanced JSON support, and robust indexing options. After comprehensive evaluation, this decision ensures data integrity and scalability for our knowledge management system.',
          status: 'accepted'
        }
      }
    },
    {
      name: 'Issue',
      item: {
        kind: 'issue',
        scope: { project: 'test-project' },
        data: {
          tracker: 'GitHub',
          external_id: 'ISSUE-001',
          title: 'Connection Pool Timeout',
          description: 'Database connections are timing out under load',
          status: 'open'
        }
      }
    },
    {
      name: 'Todo',
      item: {
        kind: 'todo',
        scope: { project: 'test-project' },
        data: {
          todo_type: 'task',
          text: 'Optimize database connection pool configuration',
          status: 'open',
          priority: 'high'
        }
      }
    },
    {
      name: 'Runbook',
      item: {
        kind: 'runbook',
        scope: { project: 'test-project' },
        data: {
          service: 'api-service',
          title: 'Database Recovery',
          description: 'Steps to recover database connectivity',
          steps: [
            {
              step_number: 1,
              description: 'Check database status',
              command: 'pg_isready -h localhost',
              expected_outcome: 'Database responds'
            }
          ]
        }
      }
    }
  ];

  async function runTests() {
    console.log('=== TESTING KNOWLEDGE TYPES INDIVIDUALLY ===\\n');

    let successCount = 0;
    let failureCount = 0;

    for (let i = 0; i < tests.length; i++) {
      const test = tests[i];
      console.log(`Testing ${test.name} (${i + 1}/${tests.length})...`);

      try {
        const result = await memoryStore([test.item]);

        if (result.stored.length > 0 && result.errors.length === 0) {
          console.log(`✅ ${test.name}: SUCCESS`);
          console.log(`   ID: ${result.stored[0].id}`);
          successCount++;
        } else {
          console.log(`❌ ${test.name}: FAILED`);
          if (result.errors.length > 0) {
            result.errors.forEach(error => {
              console.log(`   Error: ${error.message}`);
              if (error.field) console.log(`   Field: ${error.field}`);
            });
          }
          failureCount++;
        }
      } catch (error) {
        console.log(`❌ ${test.name}: EXCEPTION`);
        console.log(`   Error: ${error.message}`);
        failureCount++;
      }

      console.log(''); // Empty line for readability
    }

    console.log('=== FINAL RESULTS ===');
    console.log(`✅ Successful: ${successCount}`);
    console.log(`❌ Failed: ${failureCount}`);
    console.log(`📊 Success Rate: ${Math.round((successCount / tests.length) * 100)}%`);

    if (successCount === tests.length) {
      console.log('\\n🎉 ALL TESTS PASSED! Cortex Memory is working correctly.');
    }
  }

  runTests().catch(console.error);

}).catch(console.error);