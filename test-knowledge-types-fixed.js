import('./dist/services/memory-store.js').then(({ memoryStore }) => {
  // Test all 16 knowledge types with VALID data that meets schema requirements
  const testItems = [
    // 1. Section
    {
      kind: 'section',
      scope: { project: 'test-project' },
      data: {
        title: 'Test Section - Comprehensive Documentation',
        heading: 'Test Heading - Technical Specification',
        body_md: '# Test Section Content\n\nThis is a comprehensive test section content that includes proper markdown formatting and sufficient length to meet validation requirements.',
        tags: { test: true, type: 'documentation' }
      }
    },
    // 2. Decision (with detailed rationale for accepted status)
    {
      kind: 'decision',
      scope: { project: 'test-project' },
      data: {
        component: 'Architecture Component',
        title: 'Use PostgreSQL as Primary Database',
        rationale: 'After comprehensive evaluation of multiple database options including MySQL, MongoDB, and PostgreSQL, we have decided to use PostgreSQL as our primary database. This decision is based on PostgreSQL\'s superior ACID compliance, advanced JSON support, full-text search capabilities, and robust indexing options. The database will serve as the backbone for our Cortex Memory system, providing reliable storage for all 16 knowledge types with proper transactional support and data integrity guarantees.',
        status: 'accepted',
        alternatives_considered: [
          'MySQL - Good but limited JSON support',
          'MongoDB - NoSQL flexibility but less ACID compliance',
          'SQLite - Not suitable for production scale'
        ],
        consequences: 'PostgreSQL will provide strong consistency, complex query capabilities, and excellent scalability options.'
      }
    },
    // 3. Issue
    {
      kind: 'issue',
      scope: { project: 'test-project' },
      data: {
        tracker: 'GitHub',
        external_id: 'ISSUE-123',
        title: 'Database Connection Pool Exhaustion Under Load',
        description: 'Under high concurrent load, the database connection pool becomes exhausted, causing timeout errors for new requests. This impacts system reliability and needs immediate attention.',
        severity: 'high',
        status: 'open'
      }
    },
    // 4. Todo
    {
      kind: 'todo',
      scope: { project: 'test-project' },
      data: {
        todo_type: 'task',
        text: 'Implement connection pooling optimization for database layer',
        status: 'open',
        priority: 'high',
        assignee: 'database-team',
        due_date: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() // 7 days from now
      }
    },
    // 5. Runbook (with proper step structure)
    {
      kind: 'runbook',
      scope: { project: 'test-project' },
      data: {
        service: 'cortex-memory-api',
        title: 'Database Connection Recovery',
        description: 'Procedures for recovering from database connection issues',
        steps: [
          {
            step_number: 1,
            description: 'Check database connectivity',
            command: 'pg_isready -h localhost -p 5433',
            expected_outcome: 'Database accepts connections'
          },
          {
            step_number: 2,
            description: 'Restart application if needed',
            command: 'systemctl restart cortex-memory',
            expected_outcome: 'Service restarts successfully'
          }
        ],
        triggers: ['connection timeout', 'high error rate']
      }
    },
    // 6. Change
    {
      kind: 'change',
      scope: { project: 'test-project' },
      data: {
        change_type: 'feature_add',
        subject_ref: 'connection-pooling',
        summary: 'Add database connection pooling with configurable limits',
        details: 'Implement connection pooling with min/max connections, timeout handling, and proper resource management',
        affected_files: ['src/db/pool.ts', 'src/config/environment.ts'],
        author: 'infrastructure-team'
      }
    },
    // 7. Release Note
    {
      kind: 'release_note',
      scope: { project: 'test-project' },
      data: {
        version: '2.1.0',
        release_date: new Date().toISOString(),
        summary: 'Major performance improvements and bug fixes',
        new_features: [
          'Connection pooling optimization',
          'Enhanced validation schemas',
          'Improved error handling'
        ],
        bug_fixes: [
          'Fixed date/time field mapping',
          'Resolved UUID generation issues',
          'Corrected table name references'
        ]
      }
    },
    // 8. DDL
    {
      kind: 'ddl',
      scope: { project: 'test-project' },
      data: {
        migration_id: '001_add_connection_pooling',
        ddl_text: 'CREATE INDEX idx_connection_pool_active ON connection_logs (created_at) WHERE active = true;',
        checksum: 'abc123def456',
        description: 'Add index for active connection monitoring'
      }
    },
    // 9. PR Context
    {
      kind: 'pr_context',
      scope: { project: 'test-project' },
      data: {
        pr_number: 42,
        title: 'Implement comprehensive database connection pooling',
        description: 'This PR adds connection pooling to improve database performance under load',
        author: 'contributor',
        status: 'open',
        base_branch: 'main',
        head_branch: 'feature/connection-pooling'
      }
    },
    // 10. Entity
    {
      kind: 'entity',
      scope: { project: 'test-project' },
      data: {
        entity_type: 'service',
        name: 'cortex-memory-api',
        data: {
          version: '2.1.0',
          status: 'active',
          dependencies: ['postgresql', 'redis', 'nodejs']
        }
      }
    },
    // 11. Relation
    {
      kind: 'relation',
      scope: { project: 'test-project' },
      data: {
        from_entity_type: 'service',
        from_entity_id: 'cortex-memory-api',
        to_entity_type: 'database',
        to_entity_id: 'postgres-main',
        relation_type: 'depends_on',
        metadata: { connection_type: 'primary', critical: true }
      }
    },
    // 12. Observation
    {
      kind: 'observation',
      scope: { project: 'test-project' },
      data: {
        entity_type: 'service',
        entity_id: 'cortex-memory-api',
        observation: 'Service shows 30% performance improvement after connection pooling implementation',
        observation_type: 'performance_metric'
      }
    },
    // 13. Incident
    {
      kind: 'incident',
      scope: { project: 'test-project' },
      data: {
        title: 'Database Connection Pool Exhaustion',
        severity: 'high',
        impact: 'API response times increased by 300%, affecting all users',
        resolution_status: 'resolved',
        affected_services: ['cortex-memory-api', 'user-service'],
        root_cause_analysis: 'Connection pool size was too small for peak load conditions'
      }
    },
    // 14. Release
    {
      kind: 'release',
      scope: { project: 'test-project' },
      data: {
        version: '2.1.0',
        release_type: 'minor',
        scope: 'Performance improvements and bug fixes for database layer',
        status: 'completed',
        deployment_strategy: 'Blue-green deployment with zero downtime',
        approvers: ['tech-lead', 'devops-team']
      }
    },
    // 15. Risk
    {
      kind: 'risk',
      scope: { project: 'test-project' },
      data: {
        title: 'Database Single Point of Failure',
        category: 'technical',
        risk_level: 'high',
        probability: 'possible',
        impact_description: 'If primary database fails, all services will become unavailable',
        mitigation_strategies: [
          'Implement read replicas',
          'Set up database clustering',
          'Create automated backup and recovery procedures'
        ],
        owner: 'infrastructure-team'
      }
    },
    // 16. Assumption
    {
      kind: 'assumption',
      scope: { project: 'test-project' },
      data: {
        title: 'PostgreSQL Will Handle Current Load',
        description: 'Current PostgreSQL configuration is sufficient for handling projected user growth',
        category: 'technical',
        validation_status: 'assumed',
        impact_if_invalid: 'System will require database migration or scaling, causing service disruption',
        validation_criteria: [
          'Monitor database performance metrics',
          'Test load at 2x current capacity',
          'Review connection pool utilization'
        ],
        review_frequency: 'monthly'
      }
    }
  ];

  console.log('Testing all 16 knowledge types with comprehensive valid data...');

  memoryStore(testItems).then(result => {
    console.log('\\n=== CORTEX MEMORY COMPREHENSIVE TEST RESULTS ===');
    console.log('\\n✅ Successfully stored items:', result.stored.length);
    console.log('❌ Errors:', result.errors.length);
    console.log('📊 Success Rate:', Math.round((result.stored.length / testItems.length) * 100), '%');

    // Results by kind - all 16 types
    const allKinds = [
      'section', 'decision', 'issue', 'todo', 'runbook', 'change',
      'release_note', 'ddl', 'pr_context', 'entity', 'relation',
      'observation', 'incident', 'release', 'risk', 'assumption'
    ];

    allKinds.forEach(kind => {
      const stored = result.stored.filter(s => s.kind === kind).length;
      const errors = result.errors.filter(e => {
        const item = testItems[e.index];
        return item && item.kind === kind;
      }).length;
      const status = stored > 0 ? '✅' : '❌';
      console.log(`${status} ${kind.toUpperCase()}: ${stored} stored, ${errors} errors`);
    });

    if (result.errors.length > 0) {
      console.log('\\n🔍 Error Details:');
      result.errors.forEach((error, i) => {
        const item = testItems[error.index];
        console.log(`  ${i+1}. ${item?.kind || 'unknown'}: ${error.message}`);
      });
    }

    console.log('\\n🎯 Autonomous Context:', result.autonomous_context.user_message_suggestion);
    console.log('\\n🔄 Similar items checked:', result.autonomous_context.similar_items_checked);
    console.log('📋 Duplicates found:', result.autonomous_context.duplicates_found);

    // Final verdict
    if (result.stored.length === testItems.length) {
      console.log('\\n🎉 ALL TESTS PASSED! All 16 knowledge types working correctly.');
    } else {
      console.log(`\\n⚠️  ${testItems.length - result.stored.length} tests failed. Check errors above.`);
    }

  }).catch(error => {
    console.error('❌ Comprehensive test failed:', error.message);
    console.error('Stack:', error.stack);
  });
}).catch(console.error);