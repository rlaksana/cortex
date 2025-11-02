#!/usr/bin/env node

/**
 * Test Runner
 *
 * Executes all test scenarios and provides comprehensive reporting
 */

import { runTests, TestRunner } from './framework/test-setup';
import {
  basicKnowledgeManagement,
  advancedSearchFunctionality,
  similarityAndDeduplication,
  immutabilityAndBusinessRules,
  performanceAndScalability,
} from './scenarios/knowledge-management-tests';

/**
 * Main test execution
 */
async function main() {
  console.log('🧪 Cortex Memory MCP - Test Suite');
  console.log('='.repeat(60));

  // Define all test scenarios
  const testScenarios = [
    basicKnowledgeManagement,
    advancedSearchFunctionality,
    similarityAndDeduplication,
    immutabilityAndBusinessRules,
    performanceAndScalability,
  ];

  // Run all tests
  await runTests(testScenarios);

  // Exit with appropriate code based on results
  const runner = new TestRunner();
  const summary = runner.getSummary();

  if (summary.failed > 0 || summary.timeout > 0) {
    console.log('\n❌ Some tests failed. Check the output above for details.');
    process.exit(1);
  } else {
    console.log('\n✅ All tests passed successfully!');
    process.exit(0);
  }
}

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Run the tests
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { main };
