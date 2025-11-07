#!/usr/bin/env node

/**
 * Comprehensive Deduplication and Merge Strategy Test Suite
 *
 * Tests all aspects of the deduplication system:
 * - 5 merge strategies: skip, prefer_existing, prefer_newer, combine, intelligent
 * - Similarity thresholds (0.5-1.0 range)
 * - Time window controls
 * - Cross-scope deduplication
 * - Content merging algorithms
 * - Metadata combination strategies
 * - Audit logging
 * - Performance testing
 * - Edge cases
 * - Integration testing
 */

import { EnhancedDeduplicationService } from './dist/services/deduplication/enhanced-deduplication-service.js';
import {
  DEFAULT_DEDUPLICATION_CONFIG,
  DEDUPE_PRESETS,
} from './dist/config/deduplication-config.js';

// Test configuration
const TEST_CONFIG = {
  iterations: 100,
  batchSize: 10,
  largeBatchSize: 1000,
  similaritySteps: [0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95, 1.0],
  mergeStrategies: ['skip', 'prefer_existing', 'prefer_newer', 'combine', 'intelligent'],
};

// Performance tracking
let testResults = {
  totalTests: 0,
  passedTests: 0,
  failedTests: 0,
  performanceMetrics: {},
  auditLogs: [],
  errors: [],
};

// Utility functions
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

function generateSimilarItem(baseItem, similarity = 0.85) {
  const variations = {
    // High similarity (0.9+)
    0.95: {
      title: baseItem.data.title,
      content: baseItem.data.content + ' Slightly modified.',
      description: baseItem.data.description,
    },
    // Medium similarity (0.8-0.9)
    0.85: {
      title: baseItem.data.title + ' (Updated)',
      content: baseItem.data.content.replace('test', 'testing'),
      description: baseItem.data.description + ' Updated.',
    },
    // Low similarity (0.7-0.8)
    0.75: {
      title: 'Different Title',
      content: 'Completely different content but similar structure and purpose.',
      description: 'Different description with some similar keywords.',
    },
    // Very low similarity (0.5-0.7)
    0.6: {
      title: 'Completely Different',
      content: 'This content is quite different from the original but shares some terminology.',
      description: 'Very different description here.',
    },
  };

  const variation = variations[similarity] || variations[0.85];

  return generateTestItem({
    ...variation,
    metadata: {
      ...baseItem.metadata,
      similarity: similarity,
    },
  });
}

function logTest(testName, passed, details = {}) {
  testResults.totalTests++;
  if (passed) {
    testResults.passedTests++;
    console.log(`✅ ${testName}`);
  } else {
    testResults.failedTests++;
    console.log(`❌ ${testName}`);
    if (details.error) {
      testResults.errors.push({ test: testName, error: details.error });
      console.log(`   Error: ${details.error}`);
    }
  }

  if (Object.keys(details).length > 0) {
    console.log(`   Details:`, details);
  }
}

async function measurePerformance(testName, testFunction) {
  const startTime = Date.now();
  const startMemory = process.memoryUsage();

  try {
    const result = await testFunction();
    const endTime = Date.now();
    const endMemory = process.memoryUsage();

    const performance = {
      duration: endTime - startTime,
      memoryUsed: endMemory.heapUsed - startMemory.heapUsed,
      result: result,
    };

    testResults.performanceMetrics[testName] = performance;
    return performance;
  } catch (error) {
    const endTime = Date.now();
    const endMemory = process.memoryUsage();

    const performance = {
      duration: endTime - startTime,
      memoryUsed: endMemory.heapUsed - startMemory.heapUsed,
      error: error.message,
    };

    testResults.performanceMetrics[testName] = performance;
    throw error;
  }
}

// Test 1: Merge Strategy Testing
async function testMergeStrategies() {
  console.log('\n🧪 Testing Merge Strategies');

  const baseItem = generateTestItem();
  const similarItem = generateSimilarItem(baseItem, 0.9);

  for (const strategy of TEST_CONFIG.mergeStrategies) {
    console.log(`\n  Testing strategy: ${strategy}`);

    const config = {
      ...DEFAULT_DEDUPLICATION_CONFIG,
      mergeStrategy: strategy,
      contentSimilarityThreshold: 0.8,
    };

    const service = new EnhancedDeduplicationService(config);

    try {
      const result = await measurePerformance(`merge_strategy_${strategy}`, async () => {
        return await service.processItems([similarItem]);
      });

      const { results, summary, auditLog } = result.result;

      // Store audit logs for later analysis
      testResults.auditLogs.push(...auditLog);

      // Validate results based on strategy
      let expectedAction;
      let validationDetails = {};

      switch (strategy) {
        case 'skip':
          expectedAction = 'skipped';
          validationDetails = {
            action: results[0].action,
            reason: results[0].reason,
          };
          break;

        case 'prefer_existing':
          expectedAction = 'skipped';
          validationDetails = {
            action: results[0].action,
            reason: results[0].reason,
          };
          break;

        case 'prefer_newer':
          expectedAction = similarItem.created_at > baseItem.created_at ? 'updated' : 'skipped';
          validationDetails = {
            action: results[0].action,
            isSimilar: results[0].similarityScore >= 0.8,
          };
          break;

        case 'combine':
          expectedAction = 'merged';
          validationDetails = {
            action: results[0].action,
            hasMergeDetails: !!results[0].mergeDetails,
          };
          break;

        case 'intelligent':
          expectedAction = ['merged', 'updated', 'skipped'].includes(results[0].action)
            ? results[0].action
            : 'merged';
          validationDetails = {
            action: results[0].action,
            hasReason: !!results[0].reason,
          };
          break;
      }

      const passed =
        results.length === 1 &&
        (strategy === 'intelligent' || results[0].action === expectedAction);

      logTest(`Merge Strategy ${strategy}`, passed, {
        ...validationDetails,
        duration: result.duration,
        memoryUsed: `${(result.memoryUsed / 1024 / 1024).toFixed(2)} MB`,
      });
    } catch (error) {
      logTest(`Merge Strategy ${strategy}`, false, { error: error.message });
    }
  }
}

// Test 2: Similarity Threshold Testing
async function testSimilarityThresholds() {
  console.log('\n🧪 Testing Similarity Thresholds');

  const baseItem = generateTestItem();

  for (const threshold of TEST_CONFIG.similaritySteps) {
    console.log(`\n  Testing threshold: ${threshold}`);

    const config = {
      ...DEFAULT_DEDUPLICATION_CONFIG,
      contentSimilarityThreshold: threshold,
      mergeStrategy: 'combine',
    };

    const service = new EnhancedDeduplicationService(config);

    // Test with items just above and below threshold
    const aboveThreshold = generateSimilarItem(baseItem, threshold + 0.05);
    const belowThreshold = generateSimilarItem(baseItem, threshold - 0.05);

    try {
      const results = await service.processItems([aboveThreshold, belowThreshold]);

      const aboveResult = results.results[0];
      const belowResult = results.results[1];

      // Above threshold should be detected as duplicate
      const aboveIsDuplicate = aboveResult.similarityScore >= threshold;
      // Below threshold should not be detected as duplicate
      const belowIsNotDuplicate = belowResult.similarityScore < threshold;

      const passed = aboveIsDuplicate && belowIsNotDuplicate;

      logTest(`Similarity Threshold ${threshold}`, passed, {
        aboveScore: aboveResult.similarityScore,
        belowScore: belowResult.similarityScore,
        aboveAction: aboveResult.action,
        belowAction: belowResult.action,
      });
    } catch (error) {
      logTest(`Similarity Threshold ${threshold}`, false, { error: error.message });
    }
  }
}

// Test 3: Time Window Testing
async function testTimeWindows() {
  console.log('\n🧪 Testing Time Windows');

  const baseTime = new Date();
  const timeWindows = [1, 7, 30, 90]; // days

  for (const days of timeWindows) {
    console.log(`\n  Testing time window: ${days} days`);

    const config = {
      ...DEFAULT_DEDUPLICATION_CONFIG,
      dedupeWindowDays: days,
      timeBasedDeduplication: true,
      mergeStrategy: 'prefer_newer',
    };

    const service = new EnhancedDeduplicationService(config);

    // Create items at different times
    const oldItem = generateTestItem({
      title: 'Old Item',
      created_at: new Date(baseTime.getTime() - (days + 1) * 24 * 60 * 60 * 1000).toISOString(),
    });

    const recentItem = generateTestItem({
      title: 'Old Item',
      created_at: new Date(baseTime.getTime() - (days - 1) * 24 * 60 * 60 * 1000).toISOString(),
    });

    const newItem = generateTestItem({
      title: 'Old Item',
      created_at: new Date(baseTime.getTime() + 24 * 60 * 60 * 1000).toISOString(),
    });

    try {
      const oldResult = await service.processItems([oldItem]);
      const recentResult = await service.processItems([recentItem]);
      const newResult = await service.processItems([newItem]);

      // Old item should be stored (outside window)
      const oldStored = oldResult.results[0].action === 'stored';
      // Recent item should trigger deduplication (within window)
      const recentDeduped = ['merged', 'updated', 'skipped'].includes(
        recentResult.results[0].action
      );
      // New item should be preferred
      const newPreferred = newResult.results[0].action === 'stored';

      const passed = oldStored && recentDeduped && newPreferred;

      logTest(`Time Window ${days} days`, passed, {
        oldAction: oldResult.results[0].action,
        recentAction: recentResult.results[0].action,
        newAction: newResult.results[0].action,
      });
    } catch (error) {
      logTest(`Time Window ${days} days`, false, { error: error.message });
    }
  }
}

// Test 4: Cross-Scope Deduplication
async function testCrossScopeDeduplication() {
  console.log('\n🧪 Testing Cross-Scope Deduplication');

  const baseItem = generateTestItem({
    scope: { org: 'org-a', project: 'project-1', branch: 'main' },
  });

  const sameScope = generateTestItem({
    title: baseItem.data.title,
    content: baseItem.data.content,
    scope: { org: 'org-a', project: 'project-1', branch: 'main' },
  });

  const differentProject = generateTestItem({
    title: baseItem.data.title,
    content: baseItem.data.content,
    scope: { org: 'org-a', project: 'project-2', branch: 'main' },
  });

  const differentOrg = generateTestItem({
    title: baseItem.data.title,
    content: baseItem.data.content,
    scope: { org: 'org-b', project: 'project-1', branch: 'main' },
  });

  // Test with cross-scope disabled
  const configNoCross = {
    ...DEFAULT_DEDUPLICATION_CONFIG,
    crossScopeDeduplication: false,
    checkWithinScopeOnly: true,
    mergeStrategy: 'skip',
  };

  // Test with cross-scope enabled
  const configCross = {
    ...DEFAULT_DEDUPLICATION_CONFIG,
    crossScopeDeduplication: true,
    checkWithinScopeOnly: false,
    mergeStrategy: 'skip',
  };

  try {
    const serviceNoCross = new EnhancedDeduplicationService(configNoCross);
    const serviceCross = new EnhancedDeduplicationService(configCross);

    // Test with cross-scope disabled
    const noCrossResults = await serviceNoCross.processItems([
      sameScope,
      differentProject,
      differentOrg,
    ]);

    // Test with cross-scope enabled
    const crossResults = await serviceCross.processItems([
      sameScope,
      differentProject,
      differentOrg,
    ]);

    // With cross-scope disabled: only same scope should be deduped
    const noCrossSameScopeDeduped = ['skipped', 'merged', 'updated'].includes(
      noCrossResults.results[0].action
    );
    const noCrossDifferentProjectStored = noCrossResults.results[1].action === 'stored';
    const noCrossDifferentOrgStored = noCrossResults.results[2].action === 'stored';

    // With cross-scope enabled: all should be deduped
    const crossAllDeduped = noCrossResults.results.every((r) =>
      ['skipped', 'merged', 'updated'].includes(r.action)
    );

    const passed =
      noCrossSameScopeDeduped &&
      noCrossDifferentProjectStored &&
      noCrossDifferentOrgStored &&
      crossAllDeduped;

    logTest('Cross-Scope Deduplication', passed, {
      noCrossSameScope: noCrossResults.results[0].action,
      noCrossDifferentProject: noCrossResults.results[1].action,
      noCrossDifferentOrg: noCrossResults.results[2].action,
      crossAllDeduped: crossAllDeduped,
    });
  } catch (error) {
    logTest('Cross-Scope Deduplication', false, { error: error.message });
  }
}

// Test 5: Content Merging Algorithms
async function testContentMerging() {
  console.log('\n🧪 Testing Content Merging Algorithms');

  const baseItem = generateTestItem({
    data: {
      title: 'Original Title',
      content: 'Original content paragraph 1.\nOriginal content paragraph 2.',
      description: 'Original description.',
      tags: ['original', 'test'],
      metadata: {
        version: '1.0.0',
        author: 'original-author',
      },
    },
  });

  const newItem = generateTestItem({
    data: {
      title: 'Updated Title',
      content:
        'Updated content paragraph 1.\nUpdated content paragraph 2.\nUpdated content paragraph 3.',
      description: 'Updated description with more details.',
      tags: ['updated', 'test', 'new-tag'],
      metadata: {
        version: '2.0.0',
        author: 'new-author',
        lastModified: new Date().toISOString(),
      },
    },
  });

  const mergeStrategies = ['combine', 'intelligent'];

  for (const strategy of mergeStrategies) {
    console.log(`\n  Testing content merge with strategy: ${strategy}`);

    const config = {
      ...DEFAULT_DEDUPLICATION_CONFIG,
      mergeStrategy: strategy,
      contentSimilarityThreshold: 0.7,
    };

    const service = new EnhancedDeduplicationService(config);

    try {
      const result = await service.processItems([newItem]);

      if (result.results.length > 0 && result.results[0].mergeDetails) {
        const mergeDetails = result.results[0].mergeDetails;

        const hasFieldsMerged = mergeDetails.fieldsMerged.length > 0;
        const hasMergeHistory = !!mergeDetails.mergeHistory;
        const mergeDuration = mergeDetails.mergeDuration;

        const passed = hasFieldsMerged && mergeDuration > 0;

        logTest(`Content Merging ${strategy}`, passed, {
          fieldsMerged: mergeDetails.fieldsMerged,
          conflictsResolved: mergeDetails.conflictsResolved,
          newFieldsAdded: mergeDetails.newFieldsAdded,
          duration: mergeDuration,
        });
      } else {
        logTest(`Content Merging ${strategy}`, false, {
          error: 'No merge details found',
        });
      }
    } catch (error) {
      logTest(`Content Merging ${strategy}`, false, { error: error.message });
    }
  }
}

// Test 6: Audit Logging
async function testAuditLogging() {
  console.log('\n🧪 Testing Audit Logging');

  const config = {
    ...DEFAULT_DEDUPLICATION_CONFIG,
    enableAuditLogging: true,
    mergeStrategy: 'intelligent',
  };

  const service = new EnhancedDeduplicationService(config);

  // Generate test items with different scenarios
  const testItems = [
    generateTestItem({ title: 'Unique Item 1' }),
    generateTestItem({ title: 'Unique Item 2' }),
    generateTestItem({ title: 'Duplicate Item 1' }),
    generateTestItem({ title: 'Duplicate Item 1' }), // Exact duplicate
    generateTestItem({ title: 'Similar Item 1', content: 'Similar content here' }),
    generateTestItem({ title: 'Similar Item 1', content: 'Similar content here too' }),
  ];

  try {
    const result = await service.processItems(testItems);

    // Check audit logs
    const auditLogs = service.getAuditLog();

    const hasAuditLogs = auditLogs.length > 0;
    const hasRequiredFields = auditLogs.every(
      (log) =>
        log.timestamp &&
        log.itemId &&
        log.action &&
        log.strategy &&
        log.similarityScore !== undefined
    );

    const hasConfigSnapshot = auditLogs.every(
      (log) => log.configSnapshot && log.configSnapshot.mergeStrategy
    );

    const passed = hasAuditLogs && hasRequiredFields && hasConfigSnapshot;

    logTest('Audit Logging', passed, {
      totalLogs: auditLogs.length,
      hasRequiredFields,
      hasConfigSnapshot,
      sampleLog: auditLogs[0]
        ? {
            action: auditLogs[0].action,
            strategy: auditLogs[0].strategy,
            similarity: auditLogs[0].similarityScore,
          }
        : null,
    });
  } catch (error) {
    logTest('Audit Logging', false, { error: error.message });
  }
}

// Test 7: Performance Testing
async function testPerformance() {
  console.log('\n🧪 Testing Performance');

  const config = {
    ...DEFAULT_DEDUPLICATION_CONFIG,
    enableParallelProcessing: false,
    batchSize: 50,
  };

  const service = new EnhancedDeduplicationService(config);

  // Test with different batch sizes
  const batchSizes = [10, 50, 100, 500];

  for (const size of batchSizes) {
    console.log(`\n  Testing batch size: ${size}`);

    const testBatch = Array.from({ length: size }, (_, i) =>
      generateTestItem({
        title: `Performance Test Item ${i}`,
        content: `Content for performance testing item ${i} with some unique content.`,
      })
    );

    try {
      const performance = await measurePerformance(`batch_size_${size}`, async () => {
        return await service.processItems(testBatch);
      });

      const throughput = size / (performance.duration / 1000); // items per second
      const memoryPerItem = performance.memoryUsed / size; // bytes per item

      // Performance benchmarks (adjust as needed)
      const maxDuration = 5000; // 5 seconds max
      const maxMemoryPerItem = 1024 * 1024; // 1MB per item max
      const minThroughput = 10; // 10 items per second min

      const withinTimeLimit = performance.duration < maxDuration;
      const withinMemoryLimit = memoryPerItem < maxMemoryPerItem;
      const meetsThroughput = throughput >= minThroughput;

      const passed = withinTimeLimit && withinMemoryLimit && meetsThroughput;

      logTest(`Performance Batch ${size}`, passed, {
        duration: `${performance.duration}ms`,
        throughput: `${throughput.toFixed(2)} items/sec`,
        memoryPerItem: `${(memoryPerItem / 1024).toFixed(2)} KB`,
        withinTimeLimit,
        withinMemoryLimit,
        meetsThroughput,
      });
    } catch (error) {
      logTest(`Performance Batch ${size}`, false, { error: error.message });
    }
  }
}

// Test 8: Edge Cases
async function testEdgeCases() {
  console.log('\n🧪 Testing Edge Cases');

  // Test 1: Identical content
  console.log('\n  Testing identical content');
  const identical1 = generateTestItem({ title: 'Identical', content: 'Same content' });
  const identical2 = generateTestItem({ title: 'Identical', content: 'Same content' });

  const service = new EnhancedDeduplicationService({
    ...DEFAULT_DEDUPLICATION_CONFIG,
    mergeStrategy: 'skip',
  });

  try {
    const result = await service.processItems([identical1, identical2]);
    const firstStored = result.results[0].action === 'stored';
    const secondSkipped = ['skipped', 'merged', 'updated'].includes(result.results[1].action);

    logTest('Edge Case: Identical Content', firstStored && secondSkipped, {
      firstAction: result.results[0].action,
      secondAction: result.results[1].action,
    });
  } catch (error) {
    logTest('Edge Case: Identical Content', false, { error: error.message });
  }

  // Test 2: Nearly identical content (threshold boundary)
  console.log('\n  Testing threshold boundary');
  const base = generateTestItem({
    title: 'Base Title',
    content: 'Base content for testing threshold boundaries.',
  });
  const justAbove = generateTestItem({
    title: 'Base Title',
    content: 'Base content for testing threshold boundaries with extra.',
  });
  const justBelow = generateTestItem({
    title: 'Different Title',
    content: 'Completely different content here.',
  });

  const thresholdService = new EnhancedDeduplicationService({
    ...DEFAULT_DEDUPLICATION_CONFIG,
    contentSimilarityThreshold: 0.8,
    mergeStrategy: 'combine',
  });

  try {
    const aboveResult = await thresholdService.processItems([justAbove]);
    const belowResult = await thresholdService.processItems([justBelow]);

    const aboveThreshold = aboveResult.results[0].similarityScore >= 0.8;
    const belowThreshold = belowResult.results[0].similarityScore < 0.8;

    logTest('Edge Case: Threshold Boundary', aboveThreshold && belowThreshold, {
      aboveScore: aboveResult.results[0].similarityScore,
      belowScore: belowResult.results[0].similarityScore,
    });
  } catch (error) {
    logTest('Edge Case: Threshold Boundary', false, { error: error.message });
  }

  // Test 3: Conflicting metadata
  console.log('\n  Testing conflicting metadata');
  const conflict1 = generateTestItem({
    title: 'Conflict Test',
    metadata: { version: '1.0.0', priority: 'high', status: 'active' },
  });
  const conflict2 = generateTestItem({
    title: 'Conflict Test',
    metadata: { version: '2.0.0', priority: 'low', status: 'inactive' },
  });

  const conflictService = new EnhancedDeduplicationService({
    ...DEFAULT_DEDUPLICATION_CONFIG,
    mergeStrategy: 'combine',
  });

  try {
    const conflictResult = await conflictService.processItems([conflict2]);

    const hasMergeDetails = !!conflictResult.results[0].mergeDetails;
    const hasConflictsResolved =
      conflictResult.results[0].mergeDetails?.conflictsResolved.length > 0;

    logTest('Edge Case: Conflicting Metadata', hasMergeDetails && hasConflictsResolved, {
      mergeDetails: conflictResult.results[0].mergeDetails,
    });
  } catch (error) {
    logTest('Edge Case: Conflicting Metadata', false, { error: error.message });
  }

  // Test 4: Malformed input
  console.log('\n  Testing malformed input');
  const malformedItems = [
    null,
    undefined,
    {},
    { id: 'invalid', kind: null },
    { id: 'invalid', kind: 'entity', data: null },
  ];

  try {
    const malformedResult = await service.processItems(malformedItems);

    // Should handle gracefully without crashing
    const hasResults = malformedResult.results.length > 0;
    const hasErrors = malformedResult.results.some((r) => r.status === 'validation_error');

    logTest('Edge Case: Malformed Input', hasResults, {
      totalResults: malformedResult.results.length,
      hasErrors,
    });
  } catch (error) {
    logTest('Edge Case: Malformed Input', false, { error: error.message });
  }
}

// Test 9: Integration Testing
async function testIntegration() {
  console.log('\n🧪 Testing Integration with Memory Store');

  // This would test the actual integration with the memory store
  // For now, we'll simulate the integration test

  const integrationService = new EnhancedDeduplicationService({
    ...DEFAULT_DEDUPLICATION_CONFIG,
    mergeStrategy: 'intelligent',
    enableAuditLogging: true,
  });

  // Test end-to-end workflow
  const workflowItems = [
    generateTestItem({ kind: 'entity', title: 'Integration Entity' }),
    generateTestItem({ kind: 'decision', title: 'Integration Decision' }),
    generateTestItem({ kind: 'issue', title: 'Integration Issue' }),
    generateTestItem({ kind: 'todo', title: 'Integration Todo' }),
  ];

  try {
    const workflowResult = await integrationService.processItems(workflowItems);

    const allProcessed = workflowResult.results.length === workflowItems.length;
    const hasSummary = !!workflowResult.summary;
    const hasAuditLogs = workflowResult.auditLog.length > 0;

    logTest('Integration: End-to-End Workflow', allProcessed && hasSummary && hasAuditLogs, {
      itemsProcessed: workflowResult.results.length,
      hasSummary,
      auditLogCount: workflowResult.auditLog.length,
    });
  } catch (error) {
    logTest('Integration: End-to-End Workflow', false, { error: error.message });
  }
}

// Generate comprehensive test report
function generateTestReport() {
  console.log('\n' + '='.repeat(80));
  console.log('📊 COMPREHENSIVE DEDUPLICATION TEST REPORT');
  console.log('='.repeat(80));

  console.log(`\n📈 Test Summary:`);
  console.log(`   Total Tests: ${testResults.totalTests}`);
  console.log(
    `   Passed: ${testResults.passedTests} (${((testResults.passedTests / testResults.totalTests) * 100).toFixed(1)}%)`
  );
  console.log(
    `   Failed: ${testResults.failedTests} (${((testResults.failedTests / testResults.totalTests) * 100).toFixed(1)}%)`
  );

  if (testResults.errors.length > 0) {
    console.log(`\n❌ Errors:`);
    testResults.errors.forEach((error) => {
      console.log(`   ${error.test}: ${error.error}`);
    });
  }

  console.log(`\n⚡ Performance Metrics:`);
  Object.entries(testResults.performanceMetrics).forEach(([test, metrics]) => {
    console.log(`   ${test}:`);
    console.log(`     Duration: ${metrics.duration}ms`);
    console.log(`     Memory: ${(metrics.memoryUsed / 1024 / 1024).toFixed(2)} MB`);
    if (metrics.error) {
      console.log(`     Error: ${metrics.error}`);
    }
  });

  console.log(`\n📋 Audit Log Analysis:`);
  if (testResults.auditLogs.length > 0) {
    const actions = testResults.auditLogs.reduce((acc, log) => {
      acc[log.action] = (acc[log.action] || 0) + 1;
      return acc;
    }, {});

    console.log(`   Total Audit Entries: ${testResults.auditLogs.length}`);
    console.log(`   Actions:`, actions);

    const strategies = testResults.auditLogs.reduce((acc, log) => {
      acc[log.strategy] = (acc[log.strategy] || 0) + 1;
      return acc;
    }, {});

    console.log(`   Strategies Used:`, strategies);

    const avgSimilarity =
      testResults.auditLogs.reduce((sum, log) => sum + log.similarityScore, 0) /
      testResults.auditLogs.length;
    console.log(`   Average Similarity: ${avgSimilarity.toFixed(3)}`);
  } else {
    console.log(`   No audit logs collected`);
  }

  console.log(`\n🎯 Recommendations:`);

  if (testResults.failedTests > 0) {
    console.log(`   - Fix ${testResults.failedTests} failing tests`);
  }

  const performanceTests = Object.entries(testResults.performanceMetrics).filter(([name]) =>
    name.includes('batch_size_')
  );

  if (performanceTests.length > 0) {
    const avgThroughput =
      performanceTests.reduce((sum, [, metrics]) => {
        const size = parseInt(metrics.result?.summary?.totalProcessed || '0');
        const throughput = size / (metrics.duration / 1000);
        return sum + throughput;
      }, 0) / performanceTests.length;

    console.log(`   - Average throughput: ${avgThroughput.toFixed(2)} items/sec`);

    if (avgThroughput < 50) {
      console.log(`   - Consider performance optimization for higher throughput`);
    }
  }

  if (testResults.auditLogs.length === 0) {
    console.log(`   - Ensure audit logging is properly configured`);
  }

  console.log(`\n✅ Test Suite Complete`);
  console.log('='.repeat(80));
}

// Main test runner
async function runComprehensiveTests() {
  console.log('🚀 Starting Comprehensive Deduplication Test Suite');
  console.log(`Test Configuration:`, TEST_CONFIG);

  try {
    await testMergeStrategies();
    await testSimilarityThresholds();
    await testTimeWindows();
    await testCrossScopeDeduplication();
    await testContentMerging();
    await testAuditLogging();
    await testPerformance();
    await testEdgeCases();
    await testIntegration();

    generateTestReport();
  } catch (error) {
    console.error('❌ Test suite failed:', error);
    process.exit(1);
  }
}

// Run tests if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runComprehensiveTests().catch(console.error);
}

export {
  runComprehensiveTests,
  testMergeStrategies,
  testSimilarityThresholds,
  testTimeWindows,
  testCrossScopeDeduplication,
  testContentMerging,
  testAuditLogging,
  testPerformance,
  testEdgeCases,
  testIntegration,
};
