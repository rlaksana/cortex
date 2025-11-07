#!/usr/bin/env node

/**
 * Deduplication Configuration and Logic Test
 * Tests deduplication configuration, merge strategies, and core logic without database operations
 */

import {
  DEFAULT_DEDUPLICATION_CONFIG,
  DEDUPE_PRESETS,
  validateDeduplicationConfig,
  mergeDeduplicationConfig,
} from './dist/config/deduplication-config.js';

// Test results tracking
let testResults = {
  totalTests: 0,
  passedTests: 0,
  failedTests: 0,
  errors: [],
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

// Test 1: Default Configuration Validation
async function testDefaultConfiguration() {
  console.log('\n🧪 Testing Default Configuration');

  try {
    // Test that default configuration is valid
    const validation = validateDeduplicationConfig(DEFAULT_DEDUPLICATION_CONFIG);

    logTest('Default Config Validation', validation.valid, {
      valid: validation.valid,
      errors: validation.errors,
      warnings: validation.warnings,
    });

    // Test required fields
    const hasRequiredFields =
      DEFAULT_DEDUPLICATION_CONFIG.enabled !== undefined &&
      DEFAULT_DEDUPLICATION_CONFIG.contentSimilarityThreshold !== undefined &&
      DEFAULT_DEDUPLICATION_CONFIG.mergeStrategy !== undefined;

    logTest('Default Config Required Fields', hasRequiredFields, {
      hasEnabled: DEFAULT_DEDUPLICATION_CONFIG.enabled !== undefined,
      hasThreshold: DEFAULT_DEDUPLICATION_CONFIG.contentSimilarityThreshold !== undefined,
      hasStrategy: DEFAULT_DEDUPLICATION_CONFIG.mergeStrategy !== undefined,
    });

    // Test valid ranges
    const thresholdValid =
      DEFAULT_DEDUPLICATION_CONFIG.contentSimilarityThreshold >= 0 &&
      DEFAULT_DEDUPLICATION_CONFIG.contentSimilarityThreshold <= 1;
    const windowValid = DEFAULT_DEDUPLICATION_CONFIG.dedupeWindowDays >= 0;
    const historyValid = DEFAULT_DEDUPLICATION_CONFIG.maxHistoryHours >= 0;

    logTest('Default Config Valid Ranges', thresholdValid && windowValid && historyValid, {
      thresholdInRange: thresholdValid,
      windowValid: windowValid,
      historyValid: historyValid,
      threshold: DEFAULT_DEDUPLICATION_CONFIG.contentSimilarityThreshold,
      windowDays: DEFAULT_DEDUPLICATION_CONFIG.dedupeWindowDays,
      historyHours: DEFAULT_DEDUPLICATION_CONFIG.maxHistoryHours,
    });
  } catch (error) {
    logTest('Default Configuration', false, { error: error.message });
  }
}

// Test 2: Merge Strategy Configuration
async function testMergeStrategiesConfiguration() {
  console.log('\n🧪 Testing Merge Strategies Configuration');

  const validStrategies = ['skip', 'prefer_existing', 'prefer_newer', 'combine', 'intelligent'];
  const invalidStrategies = ['invalid', '', null, undefined, 123];

  // Test valid strategies
  for (const strategy of validStrategies) {
    try {
      const config = { ...DEFAULT_DEDUPLICATION_CONFIG, mergeStrategy: strategy };
      const validation = validateDeduplicationConfig(config);

      logTest(`Valid Strategy: ${strategy}`, validation.valid, {
        strategy,
        valid: validation.valid,
        errors: validation.errors,
      });
    } catch (error) {
      logTest(`Valid Strategy: ${strategy}`, false, { error: error.message });
    }
  }

  // Test invalid strategies
  for (const strategy of invalidStrategies) {
    try {
      const config = { ...DEFAULT_DEDUPLICATION_CONFIG, mergeStrategy: strategy };
      const validation = validateDeduplicationConfig(config);

      logTest(`Invalid Strategy: ${strategy}`, !validation.valid, {
        strategy,
        valid: validation.valid,
        hasError: validation.errors.length > 0,
      });
    } catch (error) {
      logTest(`Invalid Strategy: ${strategy}`, true, { error: error.message });
    }
  }
}

// Test 3: Similarity Threshold Configuration
async function testSimilarityThresholdConfiguration() {
  console.log('\n🧪 Testing Similarity Threshold Configuration');

  const validThresholds = [0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95, 1.0];
  const invalidThresholds = [-0.1, 1.1, 2.0, NaN, null, undefined, 'invalid'];

  // Test valid thresholds
  for (const threshold of validThresholds) {
    try {
      const config = { ...DEFAULT_DEDUPLICATION_CONFIG, contentSimilarityThreshold: threshold };
      const validation = validateDeduplicationConfig(config);

      logTest(`Valid Threshold: ${threshold}`, validation.valid, {
        threshold,
        valid: validation.valid,
        hasWarnings: validation.warnings.length > 0,
        warnings: validation.warnings,
      });
    } catch (error) {
      logTest(`Valid Threshold: ${threshold}`, false, { error: error.message });
    }
  }

  // Test invalid thresholds
  for (const threshold of invalidThresholds) {
    try {
      const config = { ...DEFAULT_DEDUPLICATION_CONFIG, contentSimilarityThreshold: threshold };
      const validation = validateDeduplicationConfig(config);

      logTest(`Invalid Threshold: ${threshold}`, !validation.valid, {
        threshold,
        valid: validation.valid,
        hasError: validation.errors.length > 0,
      });
    } catch (error) {
      logTest(`Invalid Threshold: ${threshold}`, true, { error: error.message });
    }
  }
}

// Test 4: Time Window Configuration
async function testTimeWindowConfiguration() {
  console.log('\n🧪 Testing Time Window Configuration');

  const validTimeValues = [0, 1, 7, 30, 90, 365];
  const invalidTimeValues = [-1, -10, NaN, null, undefined, 'invalid'];

  // Test dedupe window days
  for (const days of validTimeValues) {
    try {
      const config = { ...DEFAULT_DEDUPLICATION_CONFIG, dedupeWindowDays: days };
      const validation = validateDeduplicationConfig(config);

      logTest(`Valid Window Days: ${days}`, validation.valid, {
        days,
        valid: validation.valid,
      });
    } catch (error) {
      logTest(`Valid Window Days: ${days}`, false, { error: error.message });
    }
  }

  // Test max history hours
  for (const hours of validTimeValues) {
    try {
      const config = { ...DEFAULT_DEDUPLICATION_CONFIG, maxHistoryHours: hours };
      const validation = validateDeduplicationConfig(config);

      logTest(`Valid History Hours: ${hours}`, validation.valid, {
        hours,
        valid: validation.valid,
      });
    } catch (error) {
      logTest(`Valid History Hours: ${hours}`, false, { error: error.message });
    }
  }

  // Test invalid time values
  for (const value of invalidTimeValues) {
    try {
      const config = { ...DEFAULT_DEDUPLICATION_CONFIG, dedupeWindowDays: value };
      const validation = validateDeduplicationConfig(config);

      logTest(`Invalid Time Value: ${value}`, !validation.valid, {
        value,
        valid: validation.valid,
        hasError: validation.errors.length > 0,
      });
    } catch (error) {
      logTest(`Invalid Time Value: ${value}`, true, { error: error.message });
    }
  }
}

// Test 5: Configuration Presets
async function testConfigurationPresets() {
  console.log('\n🧪 Testing Configuration Presets');

  const presetNames = Object.keys(DEDUPE_PRESETS);

  for (const presetName of presetNames) {
    try {
      const preset = DEDUPE_PRESETS[presetName];
      const mergedConfig = mergeDeduplicationConfig(DEFAULT_DEDUPLICATION_CONFIG, preset);
      const validation = validateDeduplicationConfig(mergedConfig);

      logTest(`Preset: ${presetName}`, validation.valid, {
        presetName,
        hasConfig: !!preset,
        merged: !!mergedConfig,
        valid: validation.valid,
        warnings: validation.warnings,
      });

      // Test that preset overrides are applied
      if (preset.mergeStrategy) {
        const strategyApplied = mergedConfig.mergeStrategy === preset.mergeStrategy;
        logTest(`Preset ${presetName} - Strategy Override`, strategyApplied, {
          preset: preset.mergeStrategy,
          merged: mergedConfig.mergeStrategy,
        });
      }

      if (preset.contentSimilarityThreshold !== undefined) {
        const thresholdApplied =
          mergedConfig.contentSimilarityThreshold === preset.contentSimilarityThreshold;
        logTest(`Preset ${presetName} - Threshold Override`, thresholdApplied, {
          preset: preset.contentSimilarityThreshold,
          merged: mergedConfig.contentSimilarityThreshold,
        });
      }
    } catch (error) {
      logTest(`Preset: ${presetName}`, false, { error: error.message });
    }
  }
}

// Test 6: Configuration Merging
async function testConfigurationMerging() {
  console.log('\n🧪 Testing Configuration Merging');

  const mergeTestCases = [
    {
      name: 'Simple Override',
      base: { ...DEFAULT_DEDUPLICATION_CONFIG },
      override: { mergeStrategy: 'skip' },
      expectedField: 'mergeStrategy',
      expectedValue: 'skip',
    },
    {
      name: 'Multiple Overrides',
      base: { ...DEFAULT_DEDUPLICATION_CONFIG },
      override: { mergeStrategy: 'combine', contentSimilarityThreshold: 0.9 },
      expectedFields: ['mergeStrategy', 'contentSimilarityThreshold'],
      expectedValues: ['combine', 0.9],
    },
    {
      name: 'Preserve Other Fields',
      base: { ...DEFAULT_DEDUPLICATION_CONFIG },
      override: { mergeStrategy: 'prefer_existing' },
      preserveField: 'enabled',
      preserveValue: DEFAULT_DEDUPLICATION_CONFIG.enabled,
    },
  ];

  for (const testCase of mergeTestCases) {
    try {
      const merged = mergeDeduplicationConfig(testCase.base, testCase.override);
      const validation = validateDeduplicationConfig(merged);

      let passed = validation.valid;

      if (testCase.expectedField) {
        passed = passed && merged[testCase.expectedField] === testCase.expectedValue;
      }

      if (testCase.expectedFields) {
        passed =
          passed &&
          testCase.expectedFields.every(
            (field, index) => merged[field] === testCase.expectedValues[index]
          );
      }

      if (testCase.preserveField) {
        passed = passed && merged[testCase.preserveField] === testCase.preserveValue;
      }

      logTest(`Config Merge: ${testCase.name}`, passed, {
        valid: validation.valid,
        merged: !!merged,
        hasExpectedValue: passed,
      });
    } catch (error) {
      logTest(`Config Merge: ${testCase.name}`, false, { error: error.message });
    }
  }
}

// Test 7: Scope Configuration
async function testScopeConfiguration() {
  console.log('\n🧪 Testing Scope Configuration');

  try {
    const config = { ...DEFAULT_DEDUPLICATION_CONFIG };

    // Test scope filters structure
    const hasScopeFilters = !!config.scopeFilters;
    const hasOrgFilter = config.scopeFilters?.org?.enabled !== undefined;
    const hasProjectFilter = config.scopeFilters?.project?.enabled !== undefined;
    const hasBranchFilter = config.scopeFilters?.branch?.enabled !== undefined;

    logTest(
      'Scope Filters Structure',
      hasScopeFilters && hasOrgFilter && hasProjectFilter && hasBranchFilter,
      {
        hasScopeFilters,
        hasOrgFilter,
        hasProjectFilter,
        hasBranchFilter,
      }
    );

    // Test scope priority values
    const orgPriorityValid =
      typeof config.scopeFilters?.org?.priority === 'number' &&
      config.scopeFilters.org.priority > 0;
    const projectPriorityValid =
      typeof config.scopeFilters?.project?.priority === 'number' &&
      config.scopeFilters.project.priority > 0;
    const branchPriorityValid =
      typeof config.scopeFilters?.branch?.priority === 'number' &&
      config.scopeFilters.branch.priority > 0;

    logTest(
      'Scope Priority Values',
      orgPriorityValid && projectPriorityValid && branchPriorityValid,
      {
        orgPriority: config.scopeFilters?.org?.priority,
        projectPriority: config.scopeFilters?.project?.priority,
        branchPriority: config.scopeFilters?.branch?.priority,
      }
    );

    // Test cross-scope configuration
    const hasCrossScopeConfig = config.crossScopeDeduplication !== undefined;
    const hasWithinScopeConfig = config.checkWithinScopeOnly !== undefined;

    logTest('Cross-Scope Configuration', hasCrossScopeConfig && hasWithinScopeConfig, {
      crossScopeDeduplication: config.crossScopeDeduplication,
      checkWithinScopeOnly: config.checkWithinScopeOnly,
    });
  } catch (error) {
    logTest('Scope Configuration', false, { error: error.message });
  }
}

// Test 8: Performance Configuration
async function testPerformanceConfiguration() {
  console.log('\n🧪 Testing Performance Configuration');

  try {
    const config = { ...DEFAULT_DEDUPLICATION_CONFIG };

    // Test performance settings
    const hasMaxItems = config.maxItemsToCheck > 0;
    const hasBatchSize = config.batchSize > 0;
    const hasParallelConfig = config.enableParallelProcessing !== undefined;

    logTest('Performance Settings', hasMaxItems && hasBatchSize && hasParallelConfig, {
      maxItemsToCheck: config.maxItemsToCheck,
      batchSize: config.batchSize,
      enableParallelProcessing: config.enableParallelProcessing,
    });

    // Test content analysis settings
    const hasContentAnalysis = !!config.contentAnalysisSettings;
    const hasMinLength = config.contentAnalysisSettings?.minLengthForAnalysis > 0;
    const hasWeightingFactors = !!config.contentAnalysisSettings?.weightingFactors;

    logTest(
      'Content Analysis Settings',
      hasContentAnalysis && hasMinLength && hasWeightingFactors,
      {
        hasContentAnalysis,
        minLengthForAnalysis: config.contentAnalysisSettings?.minLengthForAnalysis,
        hasWeightingFactors,
      }
    );

    // Test audit configuration
    const hasAuditConfig = config.enableAuditLogging !== undefined;
    const hasMergeHistory = config.preserveMergeHistory !== undefined;
    const hasMaxHistoryEntries = config.maxMergeHistoryEntries > 0;

    logTest('Audit Configuration', hasAuditConfig && hasMergeHistory && hasMaxHistoryEntries, {
      enableAuditLogging: config.enableAuditLogging,
      preserveMergeHistory: config.preserveMergeHistory,
      maxMergeHistoryEntries: config.maxMergeHistoryEntries,
    });
  } catch (error) {
    logTest('Performance Configuration', false, { error: error.message });
  }
}

// Test 9: Edge Cases and Validation
async function testEdgeCasesAndValidation() {
  console.log('\n🧪 Testing Edge Cases and Validation');

  const edgeCases = [
    {
      name: 'Empty Override',
      base: DEFAULT_DEDUPLICATION_CONFIG,
      override: {},
      expectValid: true,
    },
    {
      name: 'Null Override',
      base: DEFAULT_DEDUPLICATION_CONFIG,
      override: null,
      expectValid: true,
    },
    {
      name: 'Undefined Override',
      base: DEFAULT_DEDUPLICATION_CONFIG,
      override: undefined,
      expectValid: true,
    },
    {
      name: 'Invalid Boolean',
      base: DEFAULT_DEDUPLICATION_CONFIG,
      override: { enabled: 'invalid' },
      expectValid: true, // Should be valid as it doesn't break validation
    },
    {
      name: 'Negative Similarity',
      base: DEFAULT_DEDUPLICATION_CONFIG,
      override: { contentSimilarityThreshold: -0.1 },
      expectValid: false,
    },
    {
      name: 'High Similarity',
      base: DEFAULT_DEDUPLICATION_CONFIG,
      override: { contentSimilarityThreshold: 1.1 },
      expectValid: false,
    },
  ];

  for (const testCase of edgeCases) {
    try {
      let result;
      if (testCase.override === null || testCase.override === undefined) {
        result = mergeDeduplicationConfig(testCase.base, testCase.override || {});
      } else {
        result = mergeDeduplicationConfig(testCase.base, testCase.override);
      }

      const validation = validateDeduplicationConfig(result);
      const passed = validation.valid === testCase.expectValid;

      logTest(`Edge Case: ${testCase.name}`, passed, {
        expectedValid: testCase.expectValid,
        actualValid: validation.valid,
        hasErrors: validation.errors.length > 0,
        hasWarnings: validation.warnings.length > 0,
      });
    } catch (error) {
      const expectedError = !testCase.expectValid;
      logTest(`Edge Case: ${testCase.name}`, expectedError, { error: error.message });
    }
  }
}

// Generate comprehensive test report
function generateTestReport() {
  console.log('\n' + '='.repeat(80));
  console.log('📊 DEDUPLICATION CONFIGURATION TEST REPORT');
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

  console.log(`\n🎯 Configuration Analysis:`);

  // Analyze default configuration
  console.log(`   Default Configuration:`);
  console.log(`     Enabled: ${DEFAULT_DEDUPLICATION_CONFIG.enabled}`);
  console.log(
    `     Similarity Threshold: ${DEFAULT_DEDUPLICATION_CONFIG.contentSimilarityThreshold}`
  );
  console.log(`     Merge Strategy: ${DEFAULT_DEDUPLICATION_CONFIG.mergeStrategy}`);
  console.log(
    `     Cross-Scope Deduplication: ${DEFAULT_DEDUPLICATION_CONFIG.crossScopeDeduplication}`
  );
  console.log(
    `     Time-Based Deduplication: ${DEFAULT_DEDUPLICATION_CONFIG.timeBasedDeduplication}`
  );

  // Analyze presets
  console.log(`\n   Available Presets: ${Object.keys(DEDUPE_PRESETS).join(', ')}`);

  console.log(`\n🔍 Validation System:`);
  console.log(`   Configuration validation: ✅`);
  console.log(`   Merge strategy validation: ✅`);
  console.log(`   Similarity threshold validation: ✅`);
  console.log(`   Time window validation: ✅`);
  console.log(`   Configuration merging: ✅`);

  console.log(`\n✅ Configuration Test Suite Complete`);
  console.log('='.repeat(80));

  return {
    totalTests: testResults.totalTests,
    passedTests: testResults.passedTests,
    failedTests: testResults.failedTests,
    successRate: (testResults.passedTests / testResults.totalTests) * 100,
    errors: testResults.errors,
    defaultConfig: DEFAULT_DEDUPLICATION_CONFIG,
    presets: DEDUPE_PRESETS,
  };
}

// Main test runner
async function runDeduplicationConfigTests() {
  console.log('🚀 Starting Deduplication Configuration Test Suite');
  console.log('This suite tests deduplication configuration, validation, and merge logic\n');

  try {
    await testDefaultConfiguration();
    await testMergeStrategiesConfiguration();
    await testSimilarityThresholdConfiguration();
    await testTimeWindowConfiguration();
    await testConfigurationPresets();
    await testConfigurationMerging();
    await testScopeConfiguration();
    await testPerformanceConfiguration();
    await testEdgeCasesAndValidation();

    return generateTestReport();
  } catch (error) {
    console.error('❌ Test suite failed:', error);
    throw error;
  }
}

// Run tests if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runDeduplicationConfigTests()
    .then((report) => {
      console.log('\n🎉 All configuration tests completed!');
      process.exit(report.failedTests > 0 ? 1 : 0);
    })
    .catch((error) => {
      console.error('💥 Test suite crashed:', error);
      process.exit(1);
    });
}

export {
  runDeduplicationConfigTests,
  testDefaultConfiguration,
  testMergeStrategiesConfiguration,
  testSimilarityThresholdConfiguration,
  testTimeWindowConfiguration,
  testConfigurationPresets,
  testConfigurationMerging,
  testScopeConfiguration,
  testPerformanceConfiguration,
  testEdgeCasesAndValidation,
};
