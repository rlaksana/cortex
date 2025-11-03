#!/usr/bin/env node

/**
 * Basic Deduplication Test
 * Quick test to verify the enhanced deduplication service works
 */

import { EnhancedDeduplicationService } from './dist/services/deduplication/enhanced-deduplication-service.js';
import { DEFAULT_DEDUPLICATION_CONFIG } from './dist/config/deduplication-config.js';

// Simple test function
function generateTestItem(overrides = {}) {
  const baseId = `test_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  return {
    id: baseId,
    kind: 'entity',
    scope: {
      org: 'test-org',
      project: 'test-project',
      branch: 'main',
    },
    data: {
      title: 'Test Entity',
      content: 'This is a test entity for deduplication testing.',
      description: 'Test description for entity',
      ...overrides,
    },
    metadata: {
      source: 'test-suite',
      version: '1.0.0',
      ...overrides.metadata,
    },
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };
}

async function testBasicDeduplication() {
  console.log('🧪 Basic Deduplication Test');

  try {
    const service = new EnhancedDeduplicationService({
      ...DEFAULT_DEDUPLICATION_CONFIG,
      mergeStrategy: 'skip',
      contentSimilarityThreshold: 0.8,
    });

    console.log('✅ Enhanced deduplication service initialized');

    // Test with unique items
    const item1 = generateTestItem({ title: 'Unique Item 1' });
    const item2 = generateTestItem({ title: 'Unique Item 2' });

    console.log('📝 Processing unique items...');
    const result1 = await service.processItems([item1, item2]);
    console.log(`✅ Processed ${result1.results.length} items`);

    // Test with duplicate items
    const duplicate = generateTestItem({ title: 'Unique Item 1' });

    console.log('📝 Processing duplicate item...');
    const result2 = await service.processItems([duplicate]);
    console.log(`✅ Processed duplicate with action: ${result2.results[0].action}`);

    // Test audit logs
    const auditLogs = service.getAuditLog();
    console.log(`📋 Audit log entries: ${auditLogs.length}`);

    // Test performance metrics
    const metrics = service.getPerformanceMetrics();
    console.log(`📊 Performance metrics:`, metrics);

    console.log('✅ Basic deduplication test completed successfully');

  } catch (error) {
    console.error('❌ Basic deduplication test failed:', error);
    process.exit(1);
  }
}

// Run the test
testBasicDeduplication();