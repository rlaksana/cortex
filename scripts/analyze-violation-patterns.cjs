
// Analyze parameter naming violations from the validation output
function analyzeViolationPatterns() {
  console.log('🔍 Analyzing Parameter Naming Violation Patterns...\n');

  // Sample data from the validation output - extract key patterns
  const violationData = {
    totalViolations: 2577,
    filesWithViolations: 518,
    violationTypes: {
      'PNC005': 2040, // Missing type annotations
      'PNC004': 346,  // Naming variations
      'PNC003': 102,  // Boolean parameter naming
      'PNC002': 19,   // Unused parameters
      'PNC001': 70    // CamelCase violations
    }
  };

  // Files with highest violation counts (from validation output)
  const highViolationFiles = [
    'src/services/metrics/system-metrics.ts',
    'src/monitoring/enhanced-observability-service.ts',
    'src/db/adapters/qdrant-adapter.ts',
    'src/services/orchestrators/memory-find-orchestrator.ts',
    'src/services/deduplication/high-performance-deduplication-service.ts',
    'src/monitoring/retry-monitoring-integration.ts',
    'src/monitoring/comprehensive-retry-dashboard.ts',
    'src/services/orchestrators/memory-store-orchestrator-qdrant.ts',
    'src/monitoring/enhanced-performance-collector.ts',
    'src/monitoring/ai-metrics.service.ts'
  ];

  console.log('📊 Overall Violation Summary:');
  console.log(`Total violations: ${violationData.totalViolations}`);
  console.log(`Files with violations: ${violationData.filesWithViolations}`);
  console.log(`Average violations per file: ${(violationData.totalViolations / violationData.filesWithViolations).toFixed(1)}\n`);

  console.log('🔍 Violation Type Breakdown:');
  Object.entries(violationData.violationTypes)
    .sort(([,a], [,b]) => b - a)
    .forEach(([code, count]) => {
      const percentage = ((count / violationData.totalViolations) * 100).toFixed(1);
      console.log(`  ${code}: ${count} violations (${percentage}%)`);
    });

  console.log('\n🎯 PNC005 (Missing Type Annotations) Analysis:');
  console.log(`This is the primary issue with ${violationData.violationTypes['PNC005']} violations (${((violationData.violationTypes['PNC005'] / violationData.totalViolations) * 100).toFixed(1)}%)`);

  console.log('\n📋 Common PNC005 Patterns:');
  console.log('1. Callback parameters: (err, result) => {...}');
  console.log('2. Event handlers: (event) => {...}');
  console.log('3. Destructured objects: ({ name, id }) => {...}');
  console.log('4. Array methods: (item) => {...}');
  console.log('5. Promise chains: (value) => {...}');

  console.log('\n🔧 PNC004 (Naming Variations) Analysis:');
  console.log(`Naming inconsistency issues: ${violationData.violationTypes['PNC004']} violations`);

  console.log('\n📋 Common PNC004 Patterns:');
  console.log('1. camelCase vs snake_case: statusCode vs status_code');
  console.log('2. Abbreviations: msg vs message, id vs identifier');
  console.log('3. Prefix consistency: isXxx vs hasXxx vs canXxx');
  console.log('4. Acronym handling: httpResponse vs HTTPResponse');

  console.log('\n🎯 Top 10 Files with Most Violations:');
  highViolationFiles.forEach((file, index) => {
    console.log(`${index + 1}. ${file}`);
  });

  console.log('\n🛠️  Fix Strategies by Priority:');

  console.log('\n🔴 HIGH PRIORITY (Automated Fixes):');
  console.log('1. PNC005 - Add type annotations to callbacks');
  console.log('   - (err: Error | null, result?: T) => void');
  console.log('   - (event: Event) => void');
  console.log('   - (item: T, index: number) => R');

  console.log('\n2. PNC003 - Boolean parameter naming');
  console.log('   - force → shouldForce');
  console.log('   - enabled → isEnabled');
  console.log('   - required → isRequired');

  console.log('\n🟡 MEDIUM PRIORITY (Semi-Automated):');
  console.log('1. PNC004 - Standardize naming variations');
  console.log('   - Choose camelCase over snake_case');
  console.log('   - Standardize abbreviations');

  console.log('\n2. PNC001 - Fix camelCase violations');
  console.log('   - Constructor parameters: PascalType → camelCase');
  console.log('   - Interface parameters: PascalType → camelCase');

  console.log('\n🟢 LOW PRIORITY (Manual Review):');
  console.log('1. PNC002 - Remove unused parameters');
  console.log('   - Review for actual usage');
  console.log('   - Consider underscore prefix for intentionally unused');

  console.log('\n📈 Estimated Effort:');
  console.log('- PNC005 (2040 violations): 2-3 hours with codemod');
  console.log('- PNC004 (346 violations): 1-2 hours with search/replace');
  console.log('- PNC003 (102 violations): 30 minutes with codemod');
  console.log('- PNC001 (70 violations): 45 minutes with manual fixes');
  console.log('- PNC002 (19 violations): 15 minutes with manual review');
  console.log('- Total estimated: 4-7 hours for 95%+ compliance');

  console.log('\n🎯 Success Metrics:');
  console.log('- Target: <50 violations remaining (95%+ compliance)');
  console.log('- PNC005: <50 violations remaining');
  console.log('- PNC004: <20 violations remaining');
  console.log('- PNC003: <10 violations remaining');
  console.log('- PNC001: <5 violations remaining');
  console.log('- PNC002: 0 violations remaining');

  console.log('\n📝 Next Actions:');
  console.log('1. Create codemod script for PNC005 fixes');
  console.log('2. Run automated fixes on test files first');
  console.log('3. Review and fix naming variations (PNC004)');
  console.log('4. Manual review of remaining violations');
  console.log('5. Update ESLint rules to prevent future violations');
}

// Run the analysis
analyzeViolationPatterns();