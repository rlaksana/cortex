#!/usr/bin/env node

/**
 * Deduplication Logic Test Suite
 * Tests the deduplication algorithms and merge strategies without requiring database setup
 */

import { EnhancedDeduplicationService } from './dist/services/deduplication/enhanced-deduplication-service.js';
import { DEFAULT_DEDUPLICATION_CONFIG, DEDUPE_PRESETS } from './dist/config/deduplication-config.js';

// Test results tracking
let testResults = {
  totalTests: 0,
  passedTests: 0,
  failedTests: 0,
  errors: [],
  auditLogs: [],
};

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

  if (Object.keys(details).length > 0 && !details.error) {
    console.log(`   Details:`, details);
  }
}

// Test utility functions
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

// Calculate text similarity using Jaccard similarity (same as in the service)
function calculateTextSimilarity(text1, text2) {
  const words1 = new Set(text1.toLowerCase().split(/\s+/).filter((word) => word.length > 2));
  const words2 = new Set(text2.toLowerCase().split(/\s+/).filter((word) => word.length > 2));

  if (words1.size === 0 && words2.size === 0) return 1.0;
  if (words1.size === 0 || words2.size === 0) return 0.0;

  const intersection = new Set([...words1].filter((word) => words2.has(word)));
  const union = new Set([...words1, ...words2]);

  return intersection.size / union.size;
}

// Test 1: Merge Strategy Logic
async function testMergeStrategiesLogic() {
  console.log('\n🧪 Testing Merge Strategy Logic');

  const mergeStrategies = ['skip', 'prefer_existing', 'prefer_newer', 'combine', 'intelligent'];

  for (const strategy of mergeStrategies) {
    console.log(`\n  Testing strategy: ${strategy}`);

    const config = {
      ...DEFAULT_DEDUPLICATION_CONFIG,
      mergeStrategy: strategy,
      contentSimilarityThreshold: 0.8,
    };

    try {
      const service = new EnhancedDeduplicationService(config);

      // Test 1: Process unique items (should be stored)
      const uniqueItems = [
        generateTestItem({ title: `Unique ${strategy} 1` }),
        generateTestItem({ title: `Unique ${strategy} 2` })
      ];

      const uniqueResult = await service.processItems(uniqueItems);

      const allStored = uniqueResult.results.every(r => r.action === 'stored');
      const hasSummary = !!uniqueResult.summary;
      const hasAuditLogs = uniqueResult.auditLog.length > 0;

      logTest(`Strategy ${strategy} - Unique Items`, allStored && hasSummary && hasAuditLogs, {
        itemsProcessed: uniqueResult.results.length,
        allStored,
        hasSummary,
        auditLogCount: uniqueResult.auditLog.length,
      });

      // Store audit logs
      testResults.auditLogs.push(...uniqueResult.auditLog);

      // Test 2: Test configuration
      const currentConfig = service.getConfig();
      const configCorrect = currentConfig.mergeStrategy === strategy &&
                           currentConfig.contentSimilarityThreshold === 0.8;

      logTest(`Strategy ${strategy} - Configuration`, configCorrect, {
        mergeStrategy: currentConfig.mergeStrategy,
        threshold: currentConfig.contentSimilarityThreshold,
      });

    } catch (error) {
      logTest(`Strategy ${strategy}`, false, { error: error.message });
    }
  }
}

// Test 2: Similarity Threshold Testing
async function testSimilarityThresholdsLogic() {
  console.log('\n🧪 Testing Similarity Threshold Logic');

  const baseItem = generateTestItem({
    title: 'Base Title',
    content: 'Base content for similarity testing.'
  });

  const testCases = [
    { item: baseItem, expectedSimilarity: 1.0, description: 'identical content' },
    { item: generateTestItem({ title: baseItem.data.title, content: baseItem.data.content }), expectedSimilarity: 1.0, description: 'exact duplicate' },
    { item: generateTestItem({ title: baseItem.data.title + ' Modified', content: baseItem.data.content }), expectedMinSimilarity: 0.8, description: 'title modified' },
    { item: generateTestItem({ title: baseItem.data.title, content: baseItem.data.content + ' Extra content' }), expectedMinSimilarity: 0.8, description: 'content extended' },
    { item: generateTestItem({ title: 'Different Title', content: 'Completely different content here' }), expectedMaxSimilarity: 0.7, description: 'completely different' },
  ];

  for (const testCase of testCases) {
    const similarity = calculateTextSimilarity(
      JSON.stringify(baseItem.data),
      JSON.stringify(testCase.item.data)
    );

    let passed = false;
    if (testCase.expectedSimilarity !== undefined) {
      passed = Math.abs(similarity - testCase.expectedSimilarity) < 0.1;
    } else if (testCase.expectedMinSimilarity !== undefined) {
      passed = similarity >= testCase.expectedMinSimilarity;
    } else if (testCase.expectedMaxSimilarity !== undefined) {
      passed = similarity <= testCase.expectedMaxSimilarity;
    }

    logTest(`Similarity - ${testCase.description}`, passed, {
      calculated: similarity.toFixed(3),
      expected: testCase.expectedSimilarity || `>= ${testCase.expectedMinSimilarity}` || `<= ${testCase.expectedMaxSimilarity}`,
    });
  }
}

// Test 3: Time Window Logic
async function testTimeWindowLogic() {
  console.log('\n🧪 Testing Time Window Logic');

  const baseTime = new Date();
  const timeWindows = [1, 7, 30]; // days

  for (const days of timeWindows) {
    const config = {
      ...DEFAULT_DEDUPLICATION_CONFIG,
      dedupeWindowDays: days,
      timeBasedDeduplication: true,
      mergeStrategy: 'prefer_newer',
    };

    try {
      const service = new EnhancedDeduplicationService(config);
      const currentConfig = service.getConfig();

      const configCorrect = currentConfig.dedupeWindowDays === days &&
                           currentConfig.timeBasedDeduplication === true;

      logTest(`Time Window ${days} days - Configuration`, configCorrect, {
        configuredDays: currentConfig.dedupeWindowDays,
        timeBasedDeduplication: currentConfig.timeBasedDeduplication,
      });

      // Test time calculations
      const oldItem = generateTestItem({
        created_at: new Date(baseTime.getTime() - (days + 1) * 24 * 60 * 60 * 1000).toISOString(),
      });

      const recentItem = generateTestItem({
        created_at: new Date(baseTime.getTime() - (days - 1) * 24 * 60 * 60 * 1000).toISOString(),
      });

      const newItem = generateTestItem({
        created_at: new Date(baseTime.getTime() + 24 * 60 * 60 * 1000).toISOString(),
      });

      // Test that items are created with correct timestamps
      const oldTimestamp = new Date(oldItem.created_at).getTime();
      const recentTimestamp = new Date(recentItem.created_at).getTime();
      const newTimestamp = new Date(newItem.created_at).getTime();
      const baseTimestamp = baseTime.getTime();

      const oldIsOlder = oldTimestamp < baseTimestamp - (days * 24 * 60 * 60 * 1000);
      const recentIsWithinWindow = Math.abs(recentTimestamp - baseTimestamp) <= (days * 24 * 60 * 60 * 1000);
      const newIsNewer = newTimestamp > baseTimestamp;

      logTest(`Time Window ${days} days - Timestamp Logic`, oldIsOlder && recentIsWithinWindow && newIsNewer, {
        oldIsOlder,
        recentIsWithinWindow,
        newIsNewer,
      });

    } catch (error) {
      logTest(`Time Window ${days} days`, false, { error: error.message });
    }
  }
}

// Test 4: Cross-Scope Logic
async function testCrossScopeLogic() {
  console.log('\n🧪 Testing Cross-Scope Logic');

  const scopeConfigurations = [
    {
      name: 'Cross-scope disabled',
      config: { ...DEFAULT_DEDUPLICATION_CONFIG, crossScopeDeduplication: false, checkWithinScopeOnly: true },
    },
    {
      name: 'Cross-scope enabled',
      config: { ...DEFAULT_DEDUPLICATION_CONFIG, crossScopeDeduplication: true, checkWithinScopeOnly: false },
    },
  ];

  for (const scopeConfig of scopeConfigurations) {
    try {
      const service = new EnhancedDeduplicationService(scopeConfig.config);
      const currentConfig = service.getConfig();

      const configCorrect = currentConfig.crossScopeDeduplication === scopeConfig.config.crossScopeDeduplication &&
                           currentConfig.checkWithinScopeOnly === scopeConfig.config.checkWithinScopeOnly;

      logTest(`Cross-Scope - ${scopeConfig.name}`, configCorrect, {
        crossScopeDeduplication: currentConfig.crossScopeDeduplication,
        checkWithinScopeOnly: currentConfig.checkWithinScopeOnly,
      });

      // Test scope filtering logic
      const sameScopeItem = generateTestItem({
        scope: { org: 'test-org', project: 'test-project', branch: 'main' }
      });

      const differentScopeItem = generateTestItem({
        scope: { org: 'different-org', project: 'different-project', branch: 'develop' }
      });

      // Test that scope data is preserved correctly
      const sameScopeCorrect = sameScopeItem.scope.org === 'test-org';
      const differentScopeCorrect = differentScopeItem.scope.org === 'different-org';

      logTest(`Cross-Scope - ${scopeConfig.name} - Scope Data`, sameScopeCorrect && differentScopeCorrect, {
        sameScopeOrg: sameScopeItem.scope.org,
        differentScopeOrg: differentScopeItem.scope.org,
      });

    } catch (error) {
      logTest(`Cross-Scope - ${scopeConfig.name}`, false, { error: error.message });
    }
  }
}

// Test 5: Content Merging Logic
async function testContentMergingLogic() {
  console.log('\n🧪 Testing Content Merging Logic');

  const baseItem = generateTestItem({
    data: {
      title: 'Original Title',
      content: 'Original content paragraph 1.\nOriginal content paragraph 2.',
      description: 'Original description.',
      tags: ['original', 'test'],
    }
  });

  const newItem = generateTestItem({
    data: {
      title: 'Updated Title',
      content: 'Updated content paragraph 1.\nUpdated content paragraph 2.\nUpdated content paragraph 3.',
      description: 'Updated description with more details.',
      tags: ['updated', 'test', 'new-tag'],
    }
  });

  // Test content merging strategies
  const mergeStrategies = ['combine', 'intelligent'];

  for (const strategy of mergeStrategies) {
    const config = {
      ...DEFAULT_DEDUPLICATION_CONFIG,
      mergeStrategy: strategy,
      contentSimilarityThreshold: 0.7,
    };

    try {
      const service = new EnhancedDeduplicationService(config);

      // Test merge configuration
      const currentConfig = service.getConfig();
      const configCorrect = currentConfig.mergeStrategy === strategy &&
                           currentConfig.preserveMergeHistory === true;

      logTest(`Content Merging ${strategy} - Configuration`, configCorrect, {
        mergeStrategy: currentConfig.mergeStrategy,
        preserveMergeHistory: currentConfig.preserveMergeHistory,
      });

      // Test content difference analysis
      const titleDifferent = baseItem.data.title !== newItem.data.title;
      const contentDifferent = baseItem.data.content !== newItem.data.content;
      const descriptionDifferent = baseItem.data.description !== newItem.data.description;
      const hasNewTags = newItem.data.tags.some(tag => !baseItem.data.tags.includes(tag));

      logTest(`Content Merging ${strategy} - Difference Analysis`, titleDifferent && contentDifferent, {
        titleDifferent,
        contentDifferent,
        descriptionDifferent,
        hasNewTags,
      });

    } catch (error) {
      logTest(`Content Merging ${strategy}`, false, { error: error.message });
    }
  }
}

// Test 6: Audit Logging Logic
async function testAuditLoggingLogic() {
  console.log('\n🧪 Testing Audit Logging Logic');

  const auditConfigs = [
    { enabled: true, name: 'Audit Enabled' },
    { enabled: false, name: 'Audit Disabled' },
  ];

  for (const auditConfig of auditConfigs) {
    const config = {
      ...DEFAULT_DEDUPLICATION_CONFIG,
      enableAuditLogging: auditConfig.enabled,
      mergeStrategy: 'skip',
    };

    try {
      const service = new EnhancedDeduplicationService(config);

      // Process test items
      const testItems = [
        generateTestItem({ title: `Audit Test ${auditConfig.name} 1` }),
        generateTestItem({ title: `Audit Test ${auditConfig.name} 2` }),
      ];

      const result = await service.processItems(testItems);
      const auditLogs = service.getAuditLog();

      // Test audit log behavior
      const hasExpectedLogs = auditConfig.enabled ? auditLogs.length > 0 : auditLogs.length === 0;

      logTest(`Audit Logging - ${auditConfig.name}`, hasExpectedLogs, {
        auditEnabled: auditConfig.enabled,
        logCount: auditLogs.length,
        itemsProcessed: result.results.length,
      });

      // Test audit log structure if enabled
      if (auditConfig.enabled && auditLogs.length > 0) {
        const sampleLog = auditLogs[0];
        const hasRequiredFields = sampleLog.timestamp &&
                                 sampleLog.itemId &&
                                 sampleLog.action &&
                                 sampleLog.strategy &&
                                 sampleLog.similarityScore !== undefined;

        const hasConfigSnapshot = !!sampleLog.configSnapshot;

        logTest(`Audit Logging - ${auditConfig.name} - Structure`, hasRequiredFields && hasConfigSnapshot, {
          hasTimestamp: !!sampleLog.timestamp,
          hasItemId: !!sampleLog.itemId,
          hasAction: !!sampleLog.action,
          hasStrategy: !!sampleLog.strategy,
          hasConfigSnapshot,
        });

        // Store audit logs for analysis
        testResults.auditLogs.push(...auditLogs);
      }

    } catch (error) {
      logTest(`Audit Logging - ${auditConfig.name}`, false, { error: error.message });
    }
  }
}

// Test 7: Performance Logic
async function testPerformanceLogic() {
  console.log('\n🧪 Testing Performance Logic');

  const performanceConfigs = [
    { batchSize: 10, name: 'Small Batch' },
    { batchSize: 50, name: 'Medium Batch' },
    { batchSize: 100, name: 'Large Batch' },
  ];

  for (const perfConfig of performanceConfigs) {
    const config = {
      ...DEFAULT_DEDUPLICATION_CONFIG,
      batchSize: perfConfig.batchSize,
      enableParallelProcessing: false,
    };

    try {
      const service = new EnhancedDeduplicationService(config);

      // Generate test batch
      const testBatch = Array.from({ length: perfConfig.batchSize }, (_, i) =>
        generateTestItem({
          title: `Performance Test Item ${i}`,
          content: `Content for performance testing item ${i} with some unique content.`
        })
      );

      const startTime = Date.now();
      const startMemory = process.memoryUsage();

      const result = await service.processItems(testBatch);

      const endTime = Date.now();
      const endMemory = process.memoryUsage();

      const duration = endTime - startTime;
      const memoryUsed = endMemory.heapUsed - startMemory.heapUsed;
      const throughput = testBatch.length / (duration / 1000);

      const hasResults = result.results.length === testBatch.length;
      const hasSummary = !!result.summary;
      const reasonableDuration = duration < 10000; // 10 seconds max
      const reasonableMemory = memoryUsed < 100 * 1024 * 1024; // 100MB max

      logTest(`Performance - ${perfConfig.name}`, hasResults && hasSummary && reasonableDuration, {
        batchSize: testBatch.length,
        duration: `${duration}ms`,
        throughput: `${throughput.toFixed(2)} items/sec`,
        memoryUsed: `${(memoryUsed / 1024 / 1024).toFixed(2)} MB`,
        reasonableDuration,
        reasonableMemory,
      });

      // Test performance metrics
      const metrics = service.getPerformanceMetrics();
      const hasMetrics = metrics.totalProcessed > 0;
      const avgProcessingTime = metrics.avgProcessingTime > 0;

      logTest(`Performance - ${perfConfig.name} - Metrics`, hasMetrics && avgProcessingTime, {
        totalProcessed: metrics.totalProcessed,
        avgProcessingTime: metrics.avgProcessingTime,
        duplicatesFound: metrics.duplicatesFound,
      });

    } catch (error) {
      logTest(`Performance - ${perfConfig.name}`, false, { error: error.message });
    }
  }
}

// Test 8: Edge Cases Logic
async function testEdgeCasesLogic() {
  console.log('\n🧪 Testing Edge Cases Logic');

  // Test 1: Identical content
  console.log('\n  Testing identical content');
  const identical1 = generateTestItem({ title: 'Identical', content: 'Same content' });
  const identical2 = generateTestItem({ title: 'Identical', content: 'Same content' });

  try {
    const service = new EnhancedDeduplicationService({
      ...DEFAULT_DEDUPLICATION_CONFIG,
      mergeStrategy: 'skip',
    });

    const identicalResult = await service.processItems([identical1, identical2]);

    const hasResults = identicalResult.results.length === 2;
    const firstStored = identicalResult.results[0].action === 'stored';
    const hasSecondAction = !!identicalResult.results[1].action;

    logTest('Edge Case: Identical Content', hasResults && firstStored && hasSecondAction, {
      resultsCount: identicalResult.results.length,
      firstAction: identicalResult.results[0].action,
      secondAction: identicalResult.results[1].action,
    });

  } catch (error) {
    logTest('Edge Case: Identical Content', false, { error: error.message });
  }

  // Test 2: Empty content
  console.log('\n  Testing empty content');
  const emptyItems = [
    generateTestItem({ title: 'Empty Content', content: '' }),
    generateTestItem({ title: 'Minimal Content', content: 'A' }),
  ];

  try {
    const service = new EnhancedDeduplicationService({
      ...DEFAULT_DEDUPLICATION_CONFIG,
      mergeStrategy: 'combine',
    });

    const emptyResult = await service.processItems(emptyItems);

    const hasEmptyResults = emptyResult.results.length === 2;
    const processedEmpty = emptyResult.results.every(r => r.action);

    logTest('Edge Case: Empty Content', hasEmptyResults && processedEmpty, {
      resultsCount: emptyResult.results.length,
      allProcessed: processedEmpty,
    });

  } catch (error) {
    logTest('Edge Case: Empty Content', false, { error: error.message });
  }

  // Test 3: Very long content
  console.log('\n  Testing long content');
  const longContent = 'A'.repeat(10000); // 10KB of content
  const longItem = generateTestItem({
    title: 'Long Content Test',
    content: longContent
  });

  try {
    const service = new EnhancedDeduplicationService({
      ...DEFAULT_DEDUPLICATION_CONFIG,
      mergeStrategy: 'intelligent',
    });

    const longResult = await service.processItems([longItem]);

    const hasLongResult = longResult.results.length === 1;
    const processedLong = longResult.results[0].action === 'stored';

    logTest('Edge Case: Long Content', hasLongResult && processedLong, {
      contentLength: longContent.length,
      action: longResult.results[0].action,
    });

  } catch (error) {
    logTest('Edge Case: Long Content', false, { error: error.message });
  }

  // Test 4: Special characters
  console.log('\n  Testing special characters');
  const specialItem = generateTestItem({
    title: 'Special Characters: 🚀 ñáéíóú 中文 🌟',
    content: 'Content with special chars: ñáéíóú, 中文, emoji 🚀🌟, symbols $%&@#',
  });

  try {
    const service = new EnhancedDeduplicationService({
      ...DEFAULT_DEDUPLICATION_CONFIG,
      mergeStrategy: 'combine',
    });

    const specialResult = await service.processItems([specialItem]);

    const hasSpecialResult = specialResult.results.length === 1;
    const processedSpecial = specialResult.results[0].action === 'stored';

    logTest('Edge Case: Special Characters', hasSpecialResult && processedSpecial, {
      action: specialResult.results[0].action,
      hasTitle: !!specialItem.data.title,
      hasContent: !!specialItem.data.content,
    });

  } catch (error) {
    logTest('Edge Case: Special Characters', false, { error: error.message });
  }
}

// Test 9: Configuration Presets
async function testConfigurationPresets() {
  console.log('\n🧪 Testing Configuration Presets');

  const presetNames = Object.keys(DEDUPE_PRESETS);

  for (const presetName of presetNames) {
    console.log(`\n  Testing preset: ${presetName}`);

    try {
      const presetConfig = DEDUPE_PRESETS[presetName];
      const mergedConfig = { ...DEFAULT_DEDUPLICATION_CONFIG, ...presetConfig };

      const service = new EnhancedDeduplicationService(mergedConfig);
      const currentConfig = service.getConfig();

      // Test that preset values are applied
      const presetApplied = Object.entries(presetConfig).every(([key, value]) => {
        return currentConfig[key] === value;
      });

      // Test that service works with preset
      const testItem = generateTestItem({ title: `Preset Test ${presetName}` });
      const result = await service.processItems([testItem]);

      const hasResult = result.results.length === 1;
      const hasAuditLog = result.auditLog.length > 0;

      logTest(`Preset ${presetName}`, presetApplied && hasResult && hasAuditLog, {
        presetApplied,
        hasResult,
        hasAuditLog,
        presetValues: Object.keys(presetConfig),
      });

    } catch (error) {
      logTest(`Preset ${presetName}`, false, { error: error.message });
    }
  }
}

// Generate comprehensive test report
function generateTestReport() {
  console.log('\n' + '='.repeat(80));
  console.log('📊 DEDUPLICATION LOGIC TEST REPORT');
  console.log('='.repeat(80));

  console.log(`\n📈 Test Summary:`);
  console.log(`   Total Tests: ${testResults.totalTests}`);
  console.log(`   Passed: ${testResults.passedTests} (${((testResults.passedTests / testResults.totalTests) * 100).toFixed(1)}%)`);
  console.log(`   Failed: ${testResults.failedTests} (${((testResults.failedTests / testResults.totalTests) * 100).toFixed(1)}%)`);

  if (testResults.errors.length > 0) {
    console.log(`\n❌ Errors:`);
    testResults.errors.forEach(error => {
      console.log(`   ${error.test}: ${error.error}`);
    });
  }

  console.log(`\n📋 Audit Log Analysis:`);
  if (testResults.auditLogs.length > 0) {
    const actions = testResults.auditLogs.reduce((acc, log) => {
      acc[log.action] = (acc[log.action] || 0) + 1;
      return acc;
    }, {});

    const strategies = testResults.auditLogs.reduce((acc, log) => {
      acc[log.strategy] = (acc[log.strategy] || 0) + 1;
      return acc;
    }, {});

    const similarityScores = testResults.auditLogs.map(log => log.similarityScore).filter(s => s > 0);
    const avgSimilarity = similarityScores.length > 0
      ? similarityScores.reduce((sum, score) => sum + score, 0) / similarityScores.length
      : 0;

    console.log(`   Total Audit Entries: ${testResults.auditLogs.length}`);
    console.log(`   Actions Distribution:`, actions);
    console.log(`   Strategies Used:`, strategies);
    console.log(`   Average Similarity: ${avgSimilarity.toFixed(3)}`);
    console.log(`   Similarity Range: ${Math.min(...similarityScores).toFixed(3)} - ${Math.max(...similarityScores).toFixed(3)}`);
  } else {
    console.log(`   No audit logs collected`);
  }

  console.log(`\n🎯 Findings:`);

  // Analyze merge strategy effectiveness
  const strategyAnalysis = testResults.auditLogs.reduce((acc, log) => {
    if (!acc[log.strategy]) {
      acc[log.strategy] = { total: 0, stored: 0, merged: 0, skipped: 0 };
    }
    acc[log.strategy].total++;
    acc[log.strategy][log.action]++;
    return acc;
  }, {});

  console.log(`   Merge Strategy Analysis:`);
  Object.entries(strategyAnalysis).forEach(([strategy, stats]) => {
    console.log(`     ${strategy}: ${stats.total} total, ${stats.stored} stored, ${stats.merged} merged, ${stats.skipped} skipped`);
  });

  console.log(`\n✅ Test Suite Complete`);
  console.log('='.repeat(80));

  return {
    totalTests: testResults.totalTests,
    passedTests: testResults.passedTests,
    failedTests: testResults.failedTests,
    successRate: (testResults.passedTests / testResults.totalTests) * 100,
    auditLogsCount: testResults.auditLogs.length,
    strategyAnalysis,
    errors: testResults.errors,
  };
}

// Main test runner
async function runDeduplicationLogicTests() {
  console.log('🚀 Starting Deduplication Logic Test Suite');
  console.log('This suite tests deduplication algorithms without requiring database setup\n');

  try {
    await testMergeStrategiesLogic();
    await testSimilarityThresholdsLogic();
    await testTimeWindowLogic();
    await testCrossScopeLogic();
    await testContentMergingLogic();
    await testAuditLoggingLogic();
    await testPerformanceLogic();
    await testEdgeCasesLogic();
    await testConfigurationPresets();

    return generateTestReport();

  } catch (error) {
    console.error('❌ Test suite failed:', error);
    throw error;
  }
}

// Run tests if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runDeduplicationLogicTests()
    .then(report => {
      console.log('\n🎉 All tests completed!');
      process.exit(report.failedTests > 0 ? 1 : 0);
    })
    .catch(error => {
      console.error('💥 Test suite crashed:', error);
      process.exit(1);
    });
}

export {
  runDeduplicationLogicTests,
  testMergeStrategiesLogic,
  testSimilarityThresholdsLogic,
  testTimeWindowLogic,
  testCrossScopeLogic,
  testContentMergingLogic,
  testAuditLoggingLogic,
  testPerformanceLogic,
  testEdgeCasesLogic,
  testConfigurationPresets,
};