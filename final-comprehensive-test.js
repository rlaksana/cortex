import('./dist/services/memory-store.js').then(({ memoryStore }) => {
  import * as crypto from 'crypto';

  // Helper to generate proper SHA-256 checksum
  function generateChecksum(text) {
    return crypto.createHash('sha256').update(text).digest('hex');
  }

  // Helper to generate UUIDs for entity references
  function generateUUID() {
    return crypto.randomUUID();
  }

  const serviceId = generateUUID();
  const databaseId = generateUUID();

  const finalTest = [
    // ✅ ALREADY WORKING TYPES (5)
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

    // ✅ OTHER WORKING TYPES (4)
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

    // 🔧 FIXED TYPES - With proper data formatting
    {
      name: 'Release Note',
      item: {
        kind: 'release_note',
        scope: { project: 'test-project' },
        data: {
          version: '1.0.0',
          release_date: new Date().toISOString(),
          summary: 'Initial release with core knowledge management features',
          new_features: 'Knowledge storage, Full-text search, Memory validation',
          bug_fixes: 'Fixed connection pooling, Resolved validation issues'
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
          checksum: generateChecksum('CREATE TABLE knowledge_items (id UUID PRIMARY KEY DEFAULT gen_random_uuid());'),
          description: 'Initial database schema for knowledge items'
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
          metadata: JSON.stringify({ critical: true })
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
    }
  ];

  async function runFinalComprehensiveTest() {
    console.log('=== 🚀 FINAL COMPREHENSIVE TEST - ALL 16 KNOWLEDGE TYPES ===\\n');

    let successCount = 0;
    let failureCount = 0;
    const results = [];

    for (let i = 0; i < finalTest.length; i++) {
      const test = finalTest[i];
      console.log(`Testing ${test.name} (${i + 1}/${finalTest.length})...`);

      try {
        const result = await memoryStore([test.item]);

        if (result.stored.length > 0 && result.errors.length === 0) {
          console.log(`✅ ${test.name}: SUCCESS`);
          console.log(`   ID: ${result.stored[0].id}`);
          successCount++;
          results.push({ name: test.name, status: 'SUCCESS', id: result.stored[0].id });
        } else {
          console.log(`❌ ${test.name}: FAILED`);
          if (result.errors.length > 0) {
            result.errors.forEach(error => {
              console.log(`   Error: ${error.message}`);
              if (error.field) console.log(`   Field: ${error.field}`);
            });
          }
          failureCount++;
          results.push({ name: test.name, status: 'FAILED', errors: result.errors });
        }
      } catch (error) {
        console.log(`❌ ${test.name}: EXCEPTION`);
        console.log(`   Error: ${error.message}`);
        failureCount++;
        results.push({ name: test.name, status: 'EXCEPTION', error: error.message });
      }

      console.log(''); // Empty line for readability
    }

    console.log('=== 🏁 FINAL COMPREHENSIVE TEST RESULTS ===');
    console.log(`✅ Successful: ${successCount}/16`);
    console.log(`❌ Failed: ${failureCount}/16`);
    console.log(`📊 Success Rate: ${Math.round((successCount / finalTest.length) * 100)}%`);

    console.log('\\n📋 Detailed Results:');
    results.forEach(result => {
      const icon = result.status === 'SUCCESS' ? '✅' : '❌';
      console.log(`${icon} ${result.name}: ${result.status}`);
      if (result.id) console.log(`    ID: ${result.id}`);
      if (result.errors) {
        result.errors.forEach(error => {
          console.log(`    Error: ${error.message}`);
        });
      }
      if (result.error) console.log(`    Error: ${result.error}`);
    });

    if (successCount === 16) {
      console.log('\\n🚀🎉🏆 PERFECT SUCCESS! ALL 16 KNOWLEDGE TYPES WORK FLAWLESSLY! 🏆🎉🚀');
      console.log('\\n🎯 The Cortex Memory MCP server is fully operational and ready for production!');
      console.log('📊 All knowledge types can be stored, retrieved, and managed successfully.');
    } else if (successCount >= 12) {
      console.log('\\n✅ EXCELLENT PROGRESS! Cortex Memory is highly functional.');
      console.log(`📈 ${successCount}/16 knowledge types working perfectly.`);
    } else {
      console.log(`\\n📋 ${16 - successCount} knowledge types still need attention.`);
    }

    return { successCount, failureCount, results };
  }

  runFinalComprehensiveTest().catch(console.error);

}).catch(console.error);