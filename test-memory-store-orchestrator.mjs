#!/usr/bin/env node

/**
 * Simple test script to verify the memory store orchestrator implementation
 * Tests business rule validation and kind-specific storage functionality
 */

import { memoryStoreOrchestrator } from '../src/services/orchestrators/memory-store-orchestrator.js';

async function testMemoryStoreOrchestrator() {
  console.log('🧪 Testing Memory Store Orchestrator Implementation...\n');

  // Test 1: Basic validation and storage
  console.log('Test 1: Basic validation and storage');
  try {
    const result = await memoryStoreOrchestrator.storeItems([
      {
        kind: 'decision',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'test-component',
          status: 'proposed',
          title: 'Test ADR',
          rationale: 'This is a test ADR for validation'
        }
      }
    ]);

    console.log('✅ Test 1 passed - Basic storage works');
    console.log(`   Stored ID: ${result.stored[0]?.id}`);
    console.log(`   Status: ${result.stored[0]?.status}`);
  } catch (error) {
    console.error('❌ Test 1 failed:', error.message);
  }

  console.log('');

  // Test 2: Business rule validation - should succeed
  console.log('Test 2: Business rule validation (valid update)');
  try {
    const result = await memoryStoreOrchestrator.storeItems([
      {
        id: 'test-decision-id',
        kind: 'decision',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'test-component',
          status: 'proposed', // Can modify proposed decisions
          title: 'Updated Test ADR',
          rationale: 'This is an updated test ADR'
        }
      }
    ]);

    console.log('✅ Test 2 passed - Business rule validation works');
  } catch (error) {
    console.error('❌ Test 2 failed:', error.message);
  }

  console.log('');

  // Test 3: Multiple knowledge types
  console.log('Test 3: Multiple knowledge types storage');
  try {
    const result = await memoryStoreOrchestrator.storeItems([
      {
        kind: 'todo',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          todo_type: 'task',
          text: 'Test todo item',
          status: 'open',
          priority: 'medium'
        }
      },
      {
        kind: 'risk',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test Risk',
          category: 'technical',
          risk_level: 'medium',
          probability: 'possible',
          impact_description: 'Test impact description',
          validation_status: 'active',
          mitigation_strategies: ['Test mitigation']
        }
      },
      {
        kind: 'entity',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          entity_type: 'user',
          name: 'test-user',
          data: { email: 'test@example.com' }
        }
      }
    ]);

    console.log('✅ Test 3 passed - Multiple knowledge types work');
    console.log(`   Stored ${result.stored.length} items successfully`);
    result.stored.forEach((item, index) => {
      console.log(`   ${index + 1}. ${item.kind}: ${item.id} (${item.status})`);
    });
  } catch (error) {
    console.error('❌ Test 3 failed:', error.message);
  }

  console.log('');

  // Test 4: Error handling
  console.log('Test 4: Error handling for invalid data');
  try {
    const result = await memoryStoreOrchestrator.storeItems([
      {
        kind: 'runbook',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          service: 'test-service',
          steps: [], // Empty steps - should fail validation
          title: 'Invalid runbook'
        }
      }
    ]);

    console.log('❌ Test 4 failed - Should have thrown validation error');
  } catch (error) {
    if (error.message.includes('steps')) {
      console.log('✅ Test 4 passed - Error handling works correctly');
    } else {
      console.error('❌ Test 4 failed - Unexpected error:', error.message);
    }
  }

  console.log('\n🎉 Memory Store Orchestrator testing completed!');
}

// Run the test
testMemoryStoreOrchestrator().catch(console.error);