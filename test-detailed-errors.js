#!/usr/bin/env node

/**
 * Detailed test of knowledge types with full error messages
 */

import { memoryStore } from './dist/services/memory-store.js';

async function testKnowledgeType(typeName, testData) {
  console.log(`\n🧪 Testing ${typeName}...`);
  try {
    const result = await memoryStore([{
      kind: typeName,
      scope: { project: "mcp-cortex" },
      data: testData
    }]);

    console.log(`Raw result:`, JSON.stringify(result, null, 2));

    if (result.stored && result.stored.length > 0 && result.stored[0]) {
      console.log(`✅ ${typeName}: SUCCESS`);
      console.log(`   ID: ${result.stored[0].id}`);
      console.log(`   Status: ${result.stored[0].status}`);
      console.log(`   Kind: ${result.stored[0].kind}`);
      return true;
    } else {
      console.log(`❌ ${typeName}: FAILED`);
      if (result.errors && result.errors.length > 0) {
        console.log(`   Error Code: ${result.errors[0].error_code}`);
        console.log(`   Message: ${result.errors[0].message}`);
        console.log(`   Field: ${result.errors[0].field || 'N/A'}`);
      } else {
        console.log(`   Unexpected result format: ${JSON.stringify(result)}`);
      }
      return false;
    }
  } catch (error) {
    console.log(`❌ ${typeName}: EXCEPTION`);
    console.log(`   Error: ${error.message}`);
    console.log(`   Stack: ${error.stack}`);
    return false;
  }
}

async function runSingleTest(typeName) {
  const testCases = {
    entity: {
      name: 'Test Component',
      entity_type: 'component',
      description: 'Test component description',
      metadata: { category: 'test' }
    },
    section: {
      title: 'Test Section',
      content: 'Test section content',
      section_type: 'documentation',
      metadata: { version: '1.0' }
    },
    release_note: {
      version: 'v1.0.0',
      release_type: 'minor',
      summary: 'Test release summary',
      features: ['Feature 1', 'Feature 2'],
      bug_fixes: ['Bug fix 1'],
      breaking_changes: [],
      upgrade_notes: ['Note 1']
    }
  };

  if (!testCases[typeName]) {
    console.log(`❌ Unknown type: ${typeName}`);
    return false;
  }

  return await testKnowledgeType(typeName, testCases[typeName]);
}

// Get the type from command line argument or test a known working one
const typeName = process.argv[2] || 'section';

console.log(`🚀 Testing ${typeName} knowledge type with detailed error output...\n`);

runSingleTest(typeName)
  .then(success => {
    console.log(`\n📊 Test ${typeName}: ${success ? 'PASSED' : 'FAILED'}`);
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    console.error('Test execution failed:', error);
    process.exit(1);
  });