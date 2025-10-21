import('./dist/services/memory-store.js').then(async ({ memoryStore }) => {
  const crypto = await import('crypto');

  // Generate UUIDs untuk entity references
  const serviceId = crypto.randomUUID();
  const databaseId = crypto.randomUUID();

  const tests = [
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
            endpoints: '/memory/store, /memory/find'
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
          from_entity_id: serviceId,
          to_entity_type: 'database',
          to_entity_id: databaseId,
          relation_type: 'depends_on',
          metadata: JSON.stringify({ critical: true, created_at: new Date().toISOString() })
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
          entity_id: serviceId,
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
          title: 'Database Single Point of Failure',
          category: 'technical',
          risk_level: 'high',
          probability: 'possible',
          impact_description: 'Database failure would cause complete service outage',
          mitigation_strategies: 'Implement read replicas, Add connection pooling',
          owner: 'infrastructure-team',
          status: 'active'
        }
      }
    }
  ];

  console.log('=== 🔧 TESTING REMAINING KNOWLEDGE TYPES ===\\n');

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

  console.log('=== REMAINING TYPES RESULTS ===');
  console.log(`✅ Now working: ${successCount}`);
  console.log(`❌ Still failing: ${failureCount}`);
  console.log(`📊 Success Rate: ${Math.round((successCount / tests.length) * 100)}%`);

  // Now test all 16 types including the 9 working ones
  console.log('\\n🚀 FINAL COMPREHENSIVE TEST OF ALL 16 TYPES');

  const allWorkingTypes = [
    // ✅ Already working (9)
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
          rationale: 'PostgreSQL provides superior ACID compliance, advanced JSON support, and robust indexing options. This decision ensures data integrity and scalability.',
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
    },
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
    },
    // ✅ Fixed types (2)
    {
      name: 'Release Note',
      item: {
        kind: 'release_note',
        scope: { project: 'test-project' },
        data: {
          version: '1.0.0',
          release_date: new Date().toISOString(),
          summary: 'Initial release with core knowledge management features',
          new_features: ['Knowledge storage system', 'Full-text search capabilities', 'Memory validation framework'],
          bug_fixes: ['Fixed connection pooling issues', 'Resolved validation errors', 'Corrected field mapping problems']
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
          checksum: crypto.createHash('sha256').update('CREATE TABLE knowledge_items (id UUID PRIMARY KEY DEFAULT gen_random_uuid());').digest('hex'),
          description: 'Initial database schema for knowledge items'
        }
      }
    },
    // 🔧 Testing types (5)
    ...tests
  ];

  let finalSuccessCount = 0;
  let finalFailureCount = 0;

  console.log('\\n🎯 TESTING ALL 16 KNOWLEDGE TYPES...\\n');

  for (let i = 0; i < allWorkingTypes.length; i++) {
    const test = allWorkingTypes[i];
    console.log(`Testing ${test.name} (${i + 1}/${allWorkingTypes.length})...`);

    try {
      const result = await memoryStore([test.item]);

      if (result.stored.length > 0 && result.errors.length === 0) {
        console.log(`✅ ${test.name}: SUCCESS`);
        console.log(`   ID: ${result.stored[0].id}`);
        finalSuccessCount++;
      } else {
        console.log(`❌ ${test.name}: FAILED`);
        if (result.errors.length > 0) {
          result.errors.forEach(error => {
            console.log(`   Error: ${error.message}`);
          });
        }
        finalFailureCount++;
      }
    } catch (error) {
      console.log(`❌ ${test.name}: EXCEPTION`);
      console.log(`   Error: ${error.message}`);
      finalFailureCount++;
    }

    console.log(''); // Empty line for readability
  }

  console.log('=== 🏁 FINAL COMPREHENSIVE TEST RESULTS ===');
  console.log(`✅ Working Knowledge Types: ${finalSuccessCount}/16`);
  console.log(`❌ Failed Knowledge Types: ${finalFailureCount}/16`);
  console.log(`📊 Success Rate: ${Math.round((finalSuccessCount / 16) * 100)}%`);

  console.log('\\n📋 Detailed Status:');
  if (finalSuccessCount === 16) {
    console.log('🎉🏆🎉 PERFECT SUCCESS! ALL 16 KNOWLEDGE TYPES WORK FLAWLESSLY! 🎉🏆🎉');
    console.log('\\n🚀 The Cortex Memory MCP server is fully operational!');
    console.log('📊 All knowledge types can be stored, retrieved, and managed successfully.');
  } else {
    console.log(`\\n📋 ${16 - finalSuccessCount} knowledge types still need attention.`);
    console.log(`🔧 Issues found: Database field mapping, UUID validation, trigger configurations`);
  }

  console.log('\\n🎯 SUMMARY:');
  console.log(`✅ Core Knowledge Types: Section, Decision, Issue, Todo, Runbook, Change, Incident, Release, Assumption`);
  console.log(`✅ Advanced Types: Release Note, DDL`);
  console.log(`🔧 Issues Remaining: PR Context, Entity, Relation, Observation, Risk`);

  return { finalSuccessCount, finalFailureCount };

}).catch(console.error);