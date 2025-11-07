#!/usr/bin/env node

/**
 * Test script for Enhanced Deduplication Service
 *
 * This script tests all the enhanced deduplication features:
 * - 5 merge strategies (skip, prefer_existing, prefer_newer, combine, intelligent)
 * - Configurable similarity thresholds (0.5-1.0 range)
 * - Time window controls (1-365 days)
 * - Scope filtering options (cross_scope_dedupe, scope_only)
 * - Comprehensive audit logging
 */

import { EnhancedDeduplicationService } from './src/services/deduplication/enhanced-deduplication-service.js';

// Test data items with various similarity levels
const testItems = [
  {
    kind: 'entity',
    id: 'test-item-1',
    scope: { project: 'test-project', org: 'test-org' },
    data: {
      title: 'Authentication Service',
      content: 'Implement OAuth 2.0 authentication with JWT tokens',
      description: 'Service for handling user authentication and authorization',
    },
    metadata: { tags: ['auth', 'security'], priority: 'high' },
    created_at: new Date().toISOString(),
  },
  {
    kind: 'entity',
    id: 'test-item-2',
    scope: { project: 'test-project', org: 'test-org' },
    data: {
      title: 'Authentication Service',
      content: 'Implement OAuth 2.0 authentication with JWT tokens and refresh tokens',
      description:
        'Service for handling user authentication and authorization with enhanced security',
    },
    metadata: { tags: ['auth', 'security'], priority: 'critical' },
    created_at: new Date(Date.now() + 1000000).toISOString(), // Newer timestamp
  },
  {
    kind: 'entity',
    id: 'test-item-3',
    scope: { project: 'different-project', org: 'test-org' },
    data: {
      title: 'Payment Gateway',
      content: 'Integration with Stripe payment processing',
      description: 'Service for handling online payments',
    },
    metadata: { tags: ['payment', 'finance'] },
    created_at: new Date().toISOString(),
  },
];

async function testMergeStrategy(strategy, config = {}) {
  console.log(`\n=== Testing Merge Strategy: ${strategy.toUpperCase()} ===`);

  const enhancedConfig = {
    enabled: true,
    contentSimilarityThreshold: 0.85,
    mergeStrategy: strategy,
    enableAuditLogging: true,
    timeBasedDeduplication: true,
    dedupeWindowDays: 7,
    crossScopeDeduplication: false,
    checkWithinScopeOnly: true,
    prioritizeSameScope: true,
    respectUpdateTimestamps: true,
    ...config,
  };

  const dedupeService = new EnhancedDeduplicationService(enhancedConfig);

  try {
    const result = await dedupeService.processItems(testItems);

    console.log(`Total Items Processed: ${result.summary.totalProcessed}`);
    console.log(`Stored: ${result.summary.actions.stored}`);
    console.log(`Merged: ${result.summary.actions.merged}`);
    console.log(`Updated: ${result.summary.actions.updated}`);
    console.log(`Skipped: ${result.summary.actions.skipped}`);
    console.log(`Processing Time: ${result.summary.duration}ms`);

    // Show audit log entries
    console.log('\n--- Audit Log Entries ---');
    result.auditLog.forEach((entry, index) => {
      console.log(`${index + 1}. Item: ${entry.itemId}`);
      console.log(`   Action: ${entry.action}`);
      console.log(`   Similarity: ${(entry.similarityScore * 100).toFixed(1)}%`);
      console.log(`   Strategy: ${entry.strategy}`);
      console.log(`   Match Type: ${entry.matchType}`);
      console.log(`   Reason: ${entry.reason}`);
      if (entry.existingId) {
        console.log(`   Existing ID: ${entry.existingId}`);
      }
      if (entry.mergeDetails) {
        console.log(`   Merge Details:`);
        console.log(`     - Strategy: ${entry.mergeDetails.strategy}`);
        console.log(`     - Fields Merged: ${entry.mergeDetails.fieldsMerged.join(', ')}`);
        console.log(
          `     - Conflicts Resolved: ${entry.mergeDetails.conflictsResolved.join(', ')}`
        );
        console.log(`     - Duration: ${entry.mergeDetails.mergeDuration}ms`);
      }
      console.log('');
    });

    return result;
  } catch (error) {
    console.error(`Error testing ${strategy} strategy:`, error);
    return null;
  }
}

async function testSimilarityThresholds() {
  console.log('\n=== Testing Different Similarity Thresholds ===');

  const thresholds = [0.5, 0.7, 0.85, 0.95];

  for (const threshold of thresholds) {
    console.log(`\n--- Threshold: ${(threshold * 100).toFixed(0)}% ---`);
    const result = await testMergeStrategy('intelligent', {
      contentSimilarityThreshold: threshold,
    });

    if (result) {
      const duplicatesFound = result.summary.similarity.duplicatesFound;
      console.log(
        `Duplicates Found: ${duplicatesFound} with ${(threshold * 100).toFixed(0)}% threshold`
      );
    }
  }
}

async function testScopeFiltering() {
  console.log('\n=== Testing Scope Filtering ===');

  // Test with cross-scope deduplication disabled
  console.log('\n--- Cross-Scope Deduplication: DISABLED ---');
  await testMergeStrategy('intelligent', {
    crossScopeDeduplication: false,
    checkWithinScopeOnly: true,
  });

  // Test with cross-scope deduplication enabled
  console.log('\n--- Cross-Scope Deduplication: ENABLED ---');
  await testMergeStrategy('intelligent', {
    crossScopeDeduplication: true,
    checkWithinScopeOnly: false,
  });
}

async function testTimeWindows() {
  console.log('\n=== Testing Time Window Controls ===');

  const timeWindows = [1, 7, 30, 365]; // days

  for (const days of timeWindows) {
    console.log(`\n--- Time Window: ${days} days ---`);
    await testMergeStrategy('prefer_newer', {
      dedupeWindowDays: days,
      maxAgeForDedupeDays: days,
      timeBasedDeduplication: true,
    });
  }
}

async function main() {
  console.log('🧪 Enhanced Deduplication Service Test Suite');
  console.log('==========================================');

  try {
    // Test all merge strategies
    console.log('\n🔀 Testing All Merge Strategies');
    await testMergeStrategy('skip');
    await testMergeStrategy('prefer_existing');
    await testMergeStrategy('prefer_newer');
    await testMergeStrategy('combine');
    await testMergeStrategy('intelligent');

    // Test similarity thresholds
    console.log('\n📊 Testing Similarity Thresholds');
    await testSimilarityThresholds();

    // Test scope filtering
    console.log('\n🎯 Testing Scope Filtering');
    await testScopeFiltering();

    // Test time windows
    console.log('\n⏰ Testing Time Windows');
    await testTimeWindows();

    console.log('\n✅ All tests completed successfully!');
  } catch (error) {
    console.error('\n❌ Test suite failed:', error);
    process.exit(1);
  }
}

// Run the tests
main().catch(console.error);
