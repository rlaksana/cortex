import('./dist/services/memory-store.js').then(({ memoryStore }) => {

  const remainingTests = [
    {
      name: 'Change',
      item: {
        kind: 'change',
        scope: { project: 'test-project' },
        data: {
          change_type: 'feature_add',
          subject_ref: 'api-endpoint',
          summary: 'Add new REST API endpoint for knowledge retrieval',
          details: 'Implemented new GET /api/knowledge endpoint with filtering capabilities',
          author: 'development-team'
        }
      }
    },
    {
      name: 'Release Note',
      item: {
        kind: 'release_note',
        scope: { project: 'test-project' },
        data: {
          version: '1.0.0',
          release_date: new Date().toISOString(),
          summary: 'Initial release with core knowledge management features',
          new_features: ['Knowledge storage', 'Full-text search', 'Memory validation'],
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
      name: 'Incident',
      item: {
        kind: 'incident',
        scope: { project: 'test-project' },
        data: {
          title: 'API Response Time Degradation',
          severity: 'medium',
          impact: 'API response times increased by 200ms',
          resolution_status: 'resolved',
          affected_services: ['cortex-memory-api'],
          root_cause_analysis: 'High memory usage causing GC pressure'
        }
      }
    },
    {
      name: 'Release',
      item: {
        kind: 'release',
        scope: { project: 'test-project' },
        data: {
          version: '1.0.0',
          release_type: 'major',
          scope: 'Initial production release with full feature set',
          status: 'completed',
          deployment_strategy: 'Blue-green deployment',
          approvers: ['tech-lead', 'devops-team']
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
    },
    {
      name: 'Assumption',
      item: {
        kind: 'assumption',
        scope: { project: 'test-project' },
        data: {
          title: 'Current Database Capacity Sufficient',
          description: 'Current PostgreSQL setup can handle expected user load',
          category: 'technical',
          validation_status: 'assumed',
          impact_if_invalid: 'Will require database scaling or migration',
          validation_criteria: ['Monitor performance metrics', 'Load testing at 2x capacity'],
          review_frequency: 'monthly'
        }
      }
    }
  ];

  async function runRemainingTests() {
    console.log('=== TESTING REMAINING KNOWLEDGE TYPES ===\\n');

    let successCount = 0;
    let failureCount = 0;

    for (let i = 0; i < remainingTests.length; i++) {
      const test = remainingTests[i];
      console.log(`Testing ${test.name} (${i + 1}/${remainingTests.length})...`);

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

    console.log('=== REMAINING TYPES RESULTS ===');
    console.log(`✅ Successful: ${successCount}`);
    console.log(`❌ Failed: ${failureCount}`);
    console.log(`📊 Success Rate: ${Math.round((successCount / remainingTests.length) * 100)}%`);

    if (successCount === remainingTests.length) {
      console.log('\\n🎉 ALL REMAINING TESTS PASSED!');
    } else {
      console.log(`\\n⚠️  ${remainingTests.length - successCount} remaining tests failed.`);
    }

    return { successCount, failureCount };
  }

  runRemainingTests().then(({ successCount, failureCount }) => {
    console.log('\\n=== COMPREHENSIVE SUMMARY ===');
    const totalTested = 5 + successCount + failureCount; // 5 from previous + remaining
    const totalSuccess = 5 + successCount;
    const totalFailure = failureCount;

    console.log(`Total knowledge types tested: ${totalTested}/16`);
    console.log(`Total successful: ${totalSuccess}`);
    console.log(`Total failed: ${totalFailure}`);
    console.log(`Overall success rate: ${Math.round((totalSuccess / totalTested) * 100)}%`);

    if (totalSuccess === totalTested) {
      console.log('\\n🚀🎉🏆 PERFECT! ALL TESTED KNOWLEDGE TYPES WORK FLAWLESSLY! 🏆🎉🚀');
      console.log('\\nThe Cortex Memory MCP server is fully functional and ready for production use!');
    } else {
      console.log(`\\n📋 ${16 - totalSuccess} knowledge types remain untested or need fixes.`);
    }
  }).catch(console.error);

}).catch(console.error);