#!/usr/bin/env node

/**
 * Test with corrected field names based on schema definitions
 */

import { MemoryStoreRequestSchema } from './dist/schemas/enhanced-validation.js';

async function testCorrectedType(typeName, testData) {
  console.log(`\n🧪 Testing ${typeName} with corrected data...`);
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
        console.log(`   Code: ${error.code || 'N/A'}`);
      });
      return false;
    }
  } catch (error) {
    console.log(`❌ ${typeName}: EXCEPTION`);
    console.log(`   Error: ${error.message}`);
    return false;
  }
}

async function runCorrectedTests() {
  console.log('🚀 Testing with corrected field mappings...\n');

  const testCases = [
    {
      type: 'entity',
      data: {
        name: 'Test Component',
        entity_type: 'component',
        description: 'Test component description'
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
      type: 'release_note',
      data: {
        version: 'v1.0.0',
        release_type: 'minor',
        summary: 'Test release summary',
        features: ['Feature 1'],
        bug_fixes: ['Bug fix 1']
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
        author: 'test-user'
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
        priority: 'medium'
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
        ]
      }
    },
    {
      type: 'release',
      data: {
        version: 'v1.0.0',
        release_type: 'minor',
        scope: 'Test scope',
        deployment_strategy: 'rolling'
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
        mitigation_strategies: ['Strategy 1']
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
    },
    {
      type: 'relation',
      data: {
        source_entity_id: '123e4567-e89b-12d3-a456-426614174000',
        target_entity_id: '123e4567-e89b-12d3-a456-426614174001',
        relation_type: 'dependency'
      }
    },
    {
      type: 'observation',
      data: {
        entity_id: '123e4567-e89b-12d3-a456-426614174000',
        observation_type: 'metric',
        value: 'Test observation value',
        confidence: 0.9
      }
    },
    {
      type: 'section',
      data: {
        title: 'Test Section',
        content: 'Test section content',
        section_type: 'documentation'
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
  console.log(`📊 CORRECTED VALIDATION RESULTS: ${successCount}/${totalCount} knowledge types valid`);
  console.log(`✅ Validation Success Rate: ${Math.round((successCount / totalCount) * 100)}%`);

  if (successCount === totalCount) {
    console.log('🎉 ALL KNOWLEDGE TYPES VALIDATION PASSED!');
    console.log('💡 Ready for database testing phase');
  } else {
    console.log(`❌ ${totalCount - successCount} types still have validation issues`);
  }

  return successCount === totalCount;
}

// Run the corrected validation tests
runCorrectedTests()
  .then(success => {
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    console.error('Test execution failed:', error);
    process.exit(1);
  });