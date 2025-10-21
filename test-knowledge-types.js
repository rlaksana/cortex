import('./dist/services/memory-store.js').then(({ memoryStore }) => {
  // Test all 16 knowledge types
  const testItems = [
    // 1. Section
    {
      kind: 'section',
      scope: { project: 'test-project' },
      data: {
        title: 'Test Section',
        heading: 'Test Heading',
        body_md: 'This is a test section content',
        tags: { test: true }
      }
    },
    // 2. Decision
    {
      kind: 'decision',
      scope: { project: 'test-project' },
      data: {
        component: 'Test Component',
        title: 'Test Decision',
        rationale: 'This is a test decision rationale',
        status: 'accepted'
      }
    },
    // 3. Issue
    {
      kind: 'issue',
      scope: { project: 'test-project' },
      data: {
        tracker: 'GitHub',
        external_id: '123',
        title: 'Test Issue',
        description: 'This is a test issue',
        status: 'open'
      }
    },
    // 4. Todo
    {
      kind: 'todo',
      scope: { project: 'test-project' },
      data: {
        scope: 'test-scope',
        todo_type: 'task',
        text: 'Test todo item',
        status: 'open',
        priority: 'medium'
      }
    },
    // 5. Runbook
    {
      kind: 'runbook',
      scope: { project: 'test-project' },
      data: {
        service: 'test-service',
        title: 'Test Runbook',
        description: 'Test runbook description',
        steps: [{ step: 'Test step 1' }, { step: 'Test step 2' }]
      }
    },
    // 6. Change
    {
      kind: 'change',
      scope: { project: 'test-project' },
      data: {
        change_type: 'feature_add',
        subject_ref: 'test-subject',
        summary: 'Test change summary',
        details: 'Test change details',
        author: 'test-author'
      }
    },
    // 7. Release Note
    {
      kind: 'release_note',
      scope: { project: 'test-project' },
      data: {
        version: '1.0.0',
        release_date: new Date().toISOString(),
        summary: 'Test release summary',
        new_features: ['Feature 1', 'Feature 2']
      }
    },
    // 8. DDL
    {
      kind: 'ddl',
      scope: { project: 'test-project' },
      data: {
        migration_id: 'test_migration',
        ddl_text: 'CREATE TABLE test (id SERIAL PRIMARY KEY);',
        checksum: 'test_checksum',
        description: 'Test DDL migration'
      }
    }
  ];

  memoryStore(testItems).then(result => {
    console.log('=== CORTEX MEMORY COMPREHENSIVE TEST RESULTS ===');
    console.log('\n✅ Successfully stored items:', result.stored.length);
    console.log('❌ Errors:', result.errors.length);

    // Results by kind
    const kinds = ['section', 'decision', 'issue', 'todo', 'runbook', 'change', 'release_note', 'ddl'];
    kinds.forEach(kind => {
      const stored = result.stored.filter(s => s.kind === kind).length;
      const errors = result.errors.filter(e => {
        const item = testItems[e.index];
        return item && item.kind === kind;
      }).length;
      const status = stored > 0 ? '✅' : '❌';
      console.log(`${status} ${kind.toUpperCase()}: ${stored} stored, ${errors} errors`);
    });

    if (result.errors.length > 0) {
      console.log('\n🔍 Error Details:');
      result.errors.forEach((error, i) => {
        const item = testItems[error.index];
        console.log(`  ${i+1}. ${item?.kind || 'unknown'}: ${error.message}`);
      });
    }

    console.log('\n🎯 Autonomous Context:', result.autonomous_context.user_message_suggestion);

  }).catch(error => {
    console.error('❌ Comprehensive test failed:', error.message);
    console.error('Stack:', error.stack);
  });
}).catch(console.error);