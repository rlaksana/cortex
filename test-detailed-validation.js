#!/usr/bin/env node

/**
 * Test specific validation errors in detail
 */

import { MemoryStoreRequestSchema } from './dist/schemas/enhanced-validation.js';

async function testSpecificType(typeName, testData) {
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
        console.log(`   Code: ${error.code || 'N/A'}`);
        if (error.received) {
          console.log(`   Received: ${JSON.stringify(error.received)}`);
        }
      });
      return false;
    }
  } catch (error) {
    console.log(`❌ ${typeName}: EXCEPTION`);
    console.log(`   Error: ${error.message}`);
    console.log(`   Stack: ${error.stack}`);
    return false;
  }
}

async function runDetailedTests() {
  console.log('🚀 Detailed validation testing...\n');

  // Test entity specifically
  await testSpecificType('entity', {
    name: 'Test Component',
    entity_type: 'component',
    description: 'Test component description',
    metadata: { category: 'test' }
  });

  // Test runbook specifically
  await testSpecificType('runbook', {
    title: 'Test Runbook',
    description: 'Test runbook description',
    service: 'test-service',
    steps: [
      { step_number: 1, action: 'Test step 1', expected_result: 'Success' }
    ],
    triggers: ['test trigger']
  });

  // Test release_note specifically
  await testSpecificType('release_note', {
    version: 'v1.0.0',
    release_type: 'minor',
    summary: 'Test release summary',
    features: ['Feature 1'],
    bug_fixes: ['Bug fix 1']
  });
}

runDetailedTests()
  .then(() => {
    console.log('\n📊 Detailed validation testing completed');
  })
  .catch(error => {
    console.error('Test execution failed:', error);
  });