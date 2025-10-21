#!/usr/bin/env node

/**
 * Test knowledge type validation only (without database)
 */

import {
  MemoryStoreRequestSchema,
  validateKnowledgeItems
} from './dist/schemas/enhanced-validation.js';

async function testValidationOnly(typeName, testData) {
  console.log(`\n🧪 Testing ${typeName} validation...`);
  try {
    // Test the validation schema directly
    const item = {
      kind: typeName,
      scope: { project: "mcp-cortex" },
      data: testData
    };

    const requestValidation = MemoryStoreRequestSchema.safeParse({ items: [item] });

    if (requestValidation.success) {
      console.log(`✅ ${typeName}: Validation SUCCESS`);
      console.log(`   Schema validation passed`);
      return true;
    } else {
      console.log(`❌ ${typeName}: Validation FAILED`);
      console.log(`   Error: ${requestValidation.error.errors[0]?.message || 'Unknown validation error'}`);
      console.log(`   Field: ${requestValidation.error.errors[0]?.path.join('.') || 'N/A'}`);
      return false;
    }
  } catch (error) {
    console.log(`❌ ${typeName}: EXCEPTION`);
    console.log(`   Error: ${error.message}`);
    return false;
  }
}

async function runValidationTests() {
  console.log('🚀 Testing knowledge type validation only (no database)...\n');

  const testCases = [
    {
      type: 'entity',
      data: {
        name: 'Test Component',
        entity_type: 'component',
        description: 'Test component description',
        metadata: { category: 'test' }
      }
    },
    {
      type: 'section',
      data: {
        title: 'Test Section',
        content: 'Test section content',
        section_type: 'documentation',
        metadata: { version: '1.0' }
      }
    },
    {
      type: 'runbook',
      data: {
        title: 'Test Runbook',
        description: 'Test runbook description',
        service: 'test-service',
        steps: [
          { step_number: 1, action: 'Test step 1', expected_result: 'Success' }
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
        rationale: 'Test decision rationale',
        status: 'accepted',
        alternatives_considered: ['Alternative A']
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
      type: 'incident',
      data: {
        severity: 'high',
        impact: 'Test impact description',
        timeline: 'Test timeline',
        resolution_status: 'open'
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
        impact_description: 'Test risk impact'
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
    }
  ];

  let successCount = 0;
  let totalCount = testCases.length;

  for (const testCase of testCases) {
    const success = await testValidationOnly(testCase.type, testCase.data);
    if (success) successCount++;
  }

  console.log('\n' + '='.repeat(60));
  console.log(`📊 VALIDATION RESULTS: ${successCount}/${totalCount} knowledge types valid`);
  console.log(`✅ Validation Success Rate: ${Math.round((successCount / totalCount) * 100)}%`);

  if (successCount === totalCount) {
    console.log('🎉 ALL KNOWLEDGE TYPES VALIDATION PASSED!');
    console.log('💡 Database connectivity is the next step for full testing');
  } else {
    console.log(`❌ ${totalCount - successCount} types have validation issues`);
  }

  return successCount === totalCount;
}

// Run the validation tests
runValidationTests()
  .then(success => {
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    console.error('Test execution failed:', error);
    process.exit(1);
  });