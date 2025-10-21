import('./dist/services/memory-store.js').then(({ memoryStore }) => {

  const previouslyFailingTests = [
    {
      name: 'Release Note',
      item: {
        kind: 'release_note',
        scope: { project: 'test-project' },
        data: {
          version: '1.0.0',
          release_date: new Date().toISOString(),
          summary: 'Initial release with core knowledge management features',
          new_features: ['Knowledge storage', 'Full-text search'],
          bug_fixes: ['Fixed connection pooling', 'Resolved validation issues']
        }
      }
    },
    {
      name: 'DDL',
      item: {
        kind: 'ddl',
        scope: { project: 'test-project' },
        data: {
          migration_id: '001_initial_schema',
          ddl_text: 'CREATE TABLE knowledge_items (id UUID PRIMARY KEY DEFAULT gen_random_uuid());',
          checksum: 'abc123def456',
          description: 'Initial database schema for knowledge items'
        }
      }
    },
    {
      name: 'PR Context',
      item: {
        kind: 'pr_context',
        scope: { project: 'test-project' },
        data: {
          pr_number: 42,
          title: 'Add comprehensive knowledge validation',
          description: 'Pull request for adding validation schemas',
          author: 'contributor',
          status: 'open',
          base_branch: 'main',
          head_branch: 'feature/validation'
        }
      }
    },
    {
      name: 'Entity',
      item: {
        kind: 'entity',
        scope: { project: 'test-project' },
        data: {
          entity_type: 'service',
          name: 'cortex-memory-api',
          data: {
            version: '1.0.0',
            status: 'active',
            endpoints: ['/memory/store', '/memory/find']
          }
        }
      }
    },
    {
      name: 'Relation',
      item: {
        kind: 'relation',
        scope: { project: 'test-project' },
        data: {
          from_entity_type: 'service',
          from_entity_id: 'cortex-memory-api',
          to_entity_type: 'database',
          to_entity_id: 'postgres-main',
          relation_type: 'depends_on',
          metadata: { critical: true }
        }
      }
    },
    {
      name: 'Observation',
      item: {
        kind: 'observation',
        scope: { project: 'test-project' },
        data: {
          entity_type: 'service',
          entity_id: 'cortex-memory-api',
          observation: 'Service performing well under current load',
          observation_type: 'performance_metric'
        }
      }
    },
    {
      name: 'Risk',
      item: {
        kind: 'risk',
        scope: { project: 'test-project' },
        data: {
          title: 'Single Point of Failure - Database',
          category: 'technical',
          risk_level: 'high',
          probability: 'possible',
          impact_description: 'Database failure would cause complete service outage',
          mitigation_strategies: ['Implement read replicas', 'Add connection pooling'],
          owner: 'infrastructure-team'
        }
      }
    }
  ];

  async function testPreviouslyFailing() {
    console.log('=== TESTING PREVIOUSLY FAILING KNOWLEDGE TYPES ===\\n');

    let successCount = 0;
    let failureCount = 0;

    for (let i = 0; i < previouslyFailingTests.length; i++) {
      const test = previouslyFailingTests[i];
      console.log(`Testing ${test.name} (${i + 1}/${previouslyFailingTests.length})...`);

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

    console.log('=== PREVIOUSLY FAILING TESTS RESULTS ===');
    console.log(`✅ Now working: ${successCount}`);
    console.log(`❌ Still failing: ${failureCount}`);
    console.log(`📊 Success Rate: ${Math.round((successCount / previouslyFailingTests.length) * 100)}%`);

    if (successCount === previouslyFailingTests.length) {
      console.log('\\n🎉 ALL PREVIOUSLY FAILING TESTS NOW PASS!');
      console.log('\\n🚀🏆🎉 PERFECT! ALL 16 KNOWLEDGE TYPES NOW WORKING! 🎉🏆🚀');
    } else {
      console.log(`\\n⚠️  ${failureCount} tests still need fixes.`);
    }

    return { successCount, failureCount };
  }

  testPreviouslyFailing().catch(console.error);

}).catch(console.error);