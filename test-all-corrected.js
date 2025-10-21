#!/usr/bin/env node

/**
 * Final test with ALL correct field names based on actual schema definitions
 */

import { MemoryStoreRequestSchema } from './dist/schemas/enhanced-validation.js';

async function testCorrectedType(typeName, testData) {
  console.log(`\n🧪 Testing ${typeName}...`);
  try {
    const item = {
      kind: typeName,
      scope: { project: "mcp-cortex" },
      data: testData
    };

    const requestValidation = MemoryStoreRequestSchema.safeParse({ items: [item] });

    if (requestValidation.success) {
      console.log(`✅ ${typeName}: Validation SUCCESS`);
      return true;
    } else {
      console.log(`❌ ${typeName}: Validation FAILED`);
      requestValidation.error.errors.forEach((error, index) => {
        console.log(`   Error ${index + 1}: ${error.message}`);
        console.log(`   Path: ${error.path.join('.')}`);
      });
      return false;
    }
  } catch (error) {
    console.log(`❌ ${typeName}: EXCEPTION`);
    console.log(`   Error: ${error.message}`);
    return false;
  }
}

async function runAllCorrectedTests() {
  console.log('🚀 Final test with ALL correct field mappings...\n');

  const testCases = [
    // Working types (confirmed)
    {
      type: 'entity',
      data: {
        entity_type: 'component',
        name: 'Test Component',
        data: { category: 'test', description: 'Test component description' }
      }
    },
    {
      type: 'section',
      data: {
        title: 'Test Section',
        heading: 'Test Heading',
        body_md: 'Test section content',
        data: { section_type: 'documentation' }
      }
    },
    {
      type: 'runbook',
      data: {
        service: 'test-service',
        title: 'Test Runbook',
        description: 'Test runbook description',
        steps: [
          {
            step_number: 1,
            description: 'Test step description',
            command: 'echo "test"',
            expected_outcome: 'Success'
          }
        ],
        triggers: ['test trigger']
      }
    },
    {
      type: 'issue',
      data: {
        tracker: 'GitHub',
        external_id: 'TEST-123',
        title: 'Test Issue',
        description: 'Test issue description',
        severity: 'medium',
        status: 'open'
      }
    },
    {
      type: 'decision',
      data: {
        component: 'test-component',
        title: 'Test Decision',
        rationale: 'This is a comprehensive rationale for the test decision that meets the 50 character minimum requirement for accepted decisions.',
        status: 'accepted',
        alternatives_considered: ['Alternative A', 'Alternative B']
      }
    },
    {
      type: 'release_note',
      data: {
        version: 'v1.0.0',
        release_date: '2025-01-01T00:00:00Z',
        summary: 'Test release summary',
        new_features: ['Feature 1'],
        bug_fixes: ['Bug fix 1'],
        breaking_changes: []
      }
    },
    // Fixed types based on actual schema definitions
    {
      type: 'todo',
      data: {
        scope: 'task',
        todo_type: 'task',
        text: 'Test todo item',
        status: 'open',
        priority: 'medium',
        assignee: 'test-user',
        due_date: '2025-12-31T23:59:59Z'
      }
    },
    {
      type: 'ddl',
      data: {
        migration_id: '001_test_table',
        ddl_text: 'CREATE TABLE test_table (id UUID PRIMARY KEY);',
        checksum: 'a'.repeat(64), // SHA-256 hash placeholder
        applied_at: '2025-01-01T00:00:00Z',
        description: 'Test table creation'
      }
    },
    {
      type: 'pr_context',
      data: {
        pr_number: 123,
        title: 'Test PR',
        description: 'Test PR description',
        author: 'test-user',
        status: 'open',
        base_branch: 'main',
        head_branch: 'feature/test'
      }
    },
    {
      type: 'relation',
      data: {
        from_entity_type: 'component',
        from_entity_id: '123e4567-e89b-12d3-a456-426614174000',
        to_entity_type: 'component',
        to_entity_id: '123e4567-e89b-12d3-a456-426614174001',
        relation_type: 'dependency',
        metadata: { strength: 'strong' }
      }
    },
    {
      type: 'observation',
      data: {
        entity_type: 'component',
        entity_id: '123e4567-e89b-12d3-a456-426614174000',
        observation: 'Test observation value',
        observation_type: 'metric',
        metadata: { source: 'test', confidence: 0.9 }
      }
    },
    {
      type: 'incident',
      data: {
        title: 'Test Incident',
        severity: 'high',
        impact: 'Test impact description',
        timeline: [
          { timestamp: '2025-01-01T00:00:00Z', description: 'Incident started' }
        ],
        resolution_status: 'open',
        affected_services: ['service1'],
        incident_commander: 'test-user'
      }
    },
    {
      type: 'release',
      data: {
        version: 'v1.0.0',
        release_type: 'minor',
        scope: 'Test scope',
        release_date: '2025-01-01T00:00:00Z',
        status: 'planned',
        deployment_strategy: 'rolling',
        approvers: ['approver1']
      }
    },
    {
      type: 'risk',
      data: {
        title: 'Test Risk',
        category: 'technical',
        risk_level: 'medium',
        probability: 'medium',
        impact_description: 'Test risk impact',
        mitigation_strategies: ['Strategy 1'],
        status: 'active',
        monitoring_indicators: ['metric1'],
        contingency_plans: ['Plan A']
      }
    },
    {
      type: 'assumption',
      data: {
        title: 'Test Assumption',
        description: 'Test assumption description',
        category: 'technical',
        validation_status: 'unvalidated',
        impact_if_invalid: 'medium',
        validation_criteria: ['Test criteria'],
        owner: 'test-user',
        monitoring_approach: 'Manual review',
        review_frequency: 'monthly'
      }
    },
    {
      type: 'change',
      data: {
        change_type: 'feature',
        subject_ref: 'test-subject',
        summary: 'Test change summary',
        details: 'Detailed change description',
        affected_files: ['file1.ts', 'file2.ts'],
        author: 'test-user',
        commit_sha: 'abc123def456'
      }
    }
  ];

  let successCount = 0;
  let totalCount = testCases.length;

  for (const testCase of testCases) {
    const success = await testCorrectedType(testCase.type, testCase.data);
    if (success) successCount++;

    // Small delay between tests
    await new Promise(resolve => setTimeout(resolve, 50));
  }

  console.log('\n' + '='.repeat(60));
  console.log(`📊 ALL CORRECTED VALIDATION RESULTS: ${successCount}/${totalCount} knowledge types valid`);
  console.log(`✅ Validation Success Rate: ${Math.round((successCount / totalCount) * 100)}%`);

  if (successCount === totalCount) {
    console.log('🎉 ALL 16 KNOWLEDGE TYPES VALIDATION PASSED!');
    console.log('💡 Ready for database testing phase');
    console.log('📋 Next steps: Start PostgreSQL and run full integration tests');
  } else {
    console.log(`❌ ${totalCount - successCount} types still have validation issues`);
    console.log('🔧 Need to fix remaining schema issues before database testing');
  }

  return successCount === totalCount;
}

// Run the all-corrected validation tests
runAllCorrectedTests()
  .then(success => {
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    console.error('Test execution failed:', error);
    process.exit(1);
  });