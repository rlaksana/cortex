#!/usr/bin/env node

/**
 * Comprehensive test of all 16 knowledge types for Cortex MCP
 */

import { memoryStore } from './dist/services/memory-store.js';

async function testKnowledgeType(typeName, testData) {
  console.log(`\n🧪 Testing ${typeName}...`);
  try {
    const result = await memoryStore({
      items: [{
        kind: typeName,
        scope: { project: "mcp-cortex" },
        data: testData
      }]
    });

    if (result.results && result.results[0] && result.results[0].status === 'success') {
      console.log(`✅ ${typeName}: SUCCESS`);
      console.log(`   ID: ${result.results[0].id}`);
      return true;
    } else {
      console.log(`❌ ${typeName}: FAILED`);
      console.log(`   Error: ${result.results?.[0]?.error || 'Unknown error'}`);
      return false;
    }
  } catch (error) {
    console.log(`❌ ${typeName}: ERROR`);
    console.log(`   Error: ${error.message}`);
    return false;
  }
}

async function runAllTests() {
  console.log('🚀 Starting comprehensive test of all 16 knowledge types...\n');

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
      type: 'relation',
      data: {
        source_entity_id: '123e4567-e89b-12d3-a456-426614174000',
        target_entity_id: '123e4567-e89b-12d3-a456-426614174001',
        relation_type: 'dependency',
        metadata: { strength: 'strong' }
      }
    },
    {
      type: 'observation',
      data: {
        entity_id: '123e4567-e89b-12d3-a456-426614174000',
        observation_type: 'metric',
        value: 'Test observation value',
        confidence: 0.9,
        metadata: { source: 'test' }
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
          { step_number: 1, action: 'Test step 1', expected_result: 'Success' },
          { step_number: 2, action: 'Test step 2', expected_result: 'Success' }
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
        status: 'open',
        labels: ['bug', 'test']
      }
    },
    {
      type: 'decision',
      data: {
        component: 'test-component',
        title: 'Test Decision',
        rationale: 'Test decision rationale',
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
        assignee: 'test-user'
      }
    },
    {
      type: 'release_note',
      data: {
        version: 'v1.0.0',
        release_type: 'minor',
        summary: 'Test release summary',
        features: ['Feature 1', 'Feature 2'],
        bug_fixes: ['Bug fix 1'],
        breaking_changes: [],
        upgrade_notes: ['Note 1']
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
        reviewers: ['reviewer1', 'reviewer2'],
        changes_summary: ['Added feature', 'Fixed bug']
      }
    },
    {
      type: 'incident',
      data: {
        severity: 'high',
        impact: 'Test impact description',
        timeline: 'Test timeline',
        resolution_status: 'open',
        affected_services: ['service1', 'service2']
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
        mitigation_strategies: ['Strategy 1', 'Strategy 2'],
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
    const success = await testKnowledgeType(testCase.type, testCase.data);
    if (success) successCount++;

    // Small delay between tests
    await new Promise(resolve => setTimeout(resolve, 100));
  }

  console.log('\n' + '='.repeat(60));
  console.log(`📊 FINAL RESULTS: ${successCount}/${totalCount} knowledge types working`);
  console.log(`✅ Success Rate: ${Math.round((successCount / totalCount) * 100)}%`);

  if (successCount === totalCount) {
    console.log('🎉 ALL KNOWLEDGE TYPES WORKING PERFECTLY!');
  } else {
    console.log(`❌ ${totalCount - successCount} types still need fixing`);
  }

  return successCount === totalCount;
}

// Run the tests
runAllTests()
  .then(success => {
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    console.error('Test execution failed:', error);
    process.exit(1);
  });