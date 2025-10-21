#!/usr/bin/env node

/**
 * Detailed test for the final 4 failing types
 */

import {
  IncidentDataSchema,
  RiskDataSchema,
  AssumptionDataSchema,
  ChangeDataSchema
} from './dist/schemas/knowledge-types.js';

function testSchemaDirectly(typeName, schema, testData) {
  console.log(`\n🧪 Testing ${typeName} schema directly...`);
  try {
    const result = schema.safeParse(testData);

    if (result.success) {
      console.log(`✅ ${typeName}: Direct schema validation SUCCESS`);
      return true;
    } else {
      console.log(`❌ ${typeName}: Direct schema validation FAILED`);
      result.error.errors.forEach((error, index) => {
        console.log(`   Error ${index + 1}: ${error.message}`);
        console.log(`   Path: ${error.path.join('.')}`);
        console.log(`   Code: ${error.code || 'N/A'}`);
      });
      return false;
    }
  } catch (error) {
    console.log(`❌ ${typeName}: Schema EXCEPTION`);
    console.log(`   Error: ${error.message}`);
    return false;
  }
}

async function runFinal4Tests() {
  console.log('🔍 Testing final 4 failing types directly against schemas...\n');

  const testCases = [
    {
      type: 'incident',
      schema: IncidentDataSchema,
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
      type: 'risk',
      schema: RiskDataSchema,
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
      schema: AssumptionDataSchema,
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
      schema: ChangeDataSchema,
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
    const success = testSchemaDirectly(testCase.type, testCase.schema, testCase.data);
    if (success) successCount++;
  }

  console.log('\n' + '='.repeat(60));
  console.log(`📊 DIRECT SCHEMA RESULTS: ${successCount}/${totalCount} schemas pass direct validation`);
  console.log(`✅ Direct Schema Success Rate: ${Math.round((successCount / totalCount) * 100)}%`);

  if (successCount === totalCount) {
    console.log('🎯 All schemas validate directly - issue is in enhanced-validation union!');
  } else {
    console.log('🔧 Schema definitions themselves have issues');
  }

  return successCount === totalCount;
}

// Run the direct schema tests
runFinal4Tests()
  .then(success => {
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    console.error('Test execution failed:', error);
    process.exit(1);
  });