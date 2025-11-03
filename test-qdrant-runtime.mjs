#!/usr/bin/env node

/**
 * Test script for Qdrant runtime verification and graceful degradation
 *
 * This script tests the Phase 0 implementation:
 * 1. Qdrant runtime detection
 * 2. Hard failure + graceful fallback
 * 3. System status endpoint
 */

import { VectorDatabase } from './src/index.js';

async function testQdrantRuntime() {
  console.log('🔍 Testing Qdrant Runtime Verification...');

  const vectorDB = new VectorDatabase();

  try {
    // Test initialization (should handle gracefully if Qdrant is down)
    console.log('📦 Initializing VectorDatabase...');
    await vectorDB.initialize();

    // Check runtime status
    console.log('🔍 Checking runtime status...');
    const runtimeStatus = vectorDB.getRuntimeStatus();
    console.log('Runtime Status:', JSON.stringify(runtimeStatus, null, 2));

    // Check degraded mode
    console.log('🔧 Degraded Mode:', vectorDB.isDegradedMode());

    // Test health check
    console.log('💓 Health Check...');
    const health = await vectorDB.getHealth();
    console.log('Health Status:', JSON.stringify(health, null, 2));

    // Test store operation in degraded mode
    console.log('💾 Testing store operation...');
    const testItems = [{
      kind: 'entity',
      content: 'Test entity for runtime verification',
      scope: { project: 'test', branch: 'main' }
    }];

    const storeResult = await vectorDB.storeItems(testItems);
    console.log('Store Result:', {
      degradedMode: vectorDB.isDegradedMode(),
      itemsProcessed: storeResult.items.length,
      errors: storeResult.errors.length
    });

    // Test search operation in degraded mode
    console.log('🔍 Testing search operation...');
    const searchResult = await vectorDB.searchItems('test query', 5);
    console.log('Search Result:', {
      degradedMode: vectorDB.isDegradedMode(),
      strategy: searchResult.strategy,
      totalResults: searchResult.total
    });

    // Test runtime status refresh
    console.log('🔄 Testing runtime status refresh...');
    const refreshedStatus = await vectorDB.refreshRuntimeStatus();
    console.log('Refreshed Status:', JSON.stringify(refreshedStatus, null, 2));

    console.log('✅ All tests completed successfully!');

  } catch (error) {
    console.error('❌ Test failed:', error);
    process.exit(1);
  }
}

// Run the test
testQdrantRuntime().catch(console.error);