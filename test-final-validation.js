#!/usr/bin/env node

/**
 * Final validation test with all correct field names based on actual schema definitions
 */

import { MemoryStoreRequestSchema } from './dist/schemas/enhanced-validation.js';

async function testFinalType(typeName, testData) {
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

async function runFinalTests() {
  console.log('🚀 Final validation testing with all correct field mappings...\n');

  const testCases = [
    {
      type: 'entity',
      data: {
        entity_type: 'component',
        name: 'Test Component',
        data: { category: 'test', description: 'Test component description' }
      }
    },
    {
      type: 'relation',
      data: {
        source_entity_id: '123e4567-e89b-12d3-a456-426614174000',
        target_entity_id: '123e4567-e89b-12d3-a456-426614174001',
        relation_type: 'dependency',
        data: { strength: 'strong' }
      }
    },
    {
      type: 'observation',
      data: {
        entity_id: '123e4567-e89b-12d3-a456-426614174000',
        observation_type: 'metric',
        value: 'Test observation value',
        confidence: 0.9,
        data: { source: 'test' }
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
      type: 'todo',
      data: {
        todo_type: 'task',
        text: 'Test todo item',
        status: 'pending',
        priority: 'medium',
        assignee: 'test-user',
        due_date: '2025-12-31T23:59:59Z'
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
    {
      type: 'ddl',
      data: {
        object_type: 'table',
        object_name: 'test_table',
        operation_type: 'CREATE',
        sql_statement: 'CREATE TABLE test_table (id UUID PRIMARY KEY);',
        checksum: 'abc123',
        version: '1.0.0'
      }
    },
    {
      type: 'pr_context',
      data: {
        pr_number: 123,
        title: 'Test PR',
        description: 'Test PR description',
        source_branch: 'feature/test',
        target_branch: 'main',
        author: 'test-user',
        reviewers: ['reviewer1'],
        changes_summary: ['Added feature', 'Fixed bug']
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
        affected_services: ['service1']
      }
    },
    {
      type: 'release',
      data: {
        version: 'v1.0.0',
        release_type: 'minor',
        scope: 'Test scope',
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
        status: 'active'
      }
    },
    {
      type: 'assumption',
      data: {
        description: 'Test assumption description',
        category: 'technical',
        validation_status: 'unvalidated',
        impact_if_invalid: 'medium'
      }
    },
    {
      type: 'change',
      data: {
        change_type: 'feature',
        subject_ref: 'test-subject',
        summary: 'Test change summary',
        author: 'test-user',
        commit_sha: 'abc123def456'
      }
    }
  ];

  let successCount = 0;
  let totalCount = testCases.length;

  for (const testCase of testCases) {
    const success = await testFinalType(testCase.type, testCase.data);
    if (success) successCount++;

    // Small delay between tests
    await new Promise(resolve => setTimeout(resolve, 50));
  }

  console.log('\n' + '='.repeat(60));
  console.log(`📊 FINAL VALIDATION RESULTS: ${successCount}/${totalCount} knowledge types valid`);
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

// Run the final validation tests
runFinalTests()
  .then(success => {
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    console.error('Test execution failed:', error);
    process.exit(1);
  });