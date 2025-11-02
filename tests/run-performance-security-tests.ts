#!/usr/bin/env node

/**
 * Cortex MCP Performance & Security Test Runner
 *
 * Executes comprehensive performance and security testing
 * for production readiness validation
 *
 * @version 1.0.0
 */

import { PerformanceSecurityTester } from './performance-security-test-suite';
import { logger } from '../utils/logger';
import { writeFileSync } from 'fs';
import { join } from 'path';

async function main() {
  logger.info('🚀 Starting Cortex MCP Performance & Security Testing Suite');
  logger.info('==========================================================');

  const tester = new PerformanceSecurityTester();
  const startTime = Date.now();

  try {
    // Run comprehensive test suite
    const results = await tester.runFullTestSuite();

    // Generate detailed report
    const report = tester.generateReport(results);

    // Save report to file
    const reportPath = join(process.cwd(), 'PERFORMANCE_SECURITY_ASSESSMENT_REPORT.md');
    writeFileSync(reportPath, report);

    // Save raw results as JSON
    const jsonPath = join(process.cwd(), 'performance-security-test-results.json');
    writeFileSync(jsonPath, JSON.stringify(results, null, 2));

    const totalTime = Date.now() - startTime;

    // Print summary to console
    console.log('\n' + '='.repeat(60));
    console.log('🎯 CORTEX MCP PERFORMANCE & SECURITY TEST RESULTS');
    console.log('='.repeat(60));
    console.log(`⏱️  Total Test Time: ${(totalTime / 1000).toFixed(2)}s`);
    console.log(`📊 Total Tests: ${results.summary.totalTests}`);
    console.log(
      `✅ Passed: ${results.summary.passedTests} (${((results.summary.passedTests / results.summary.totalTests) * 100).toFixed(1)}%)`
    );
    console.log(
      `❌ Failed: ${results.summary.failedTests} (${((results.summary.failedTests / results.summary.totalTests) * 100).toFixed(1)}%)`
    );
    console.log(`🔒 Security Vulnerabilities: ${results.summary.vulnerabilities}`);
    console.log(`⚡ Avg Response Time: ${results.summary.avgResponseTime.toFixed(2)}ms`);
    console.log(`📈 Max Response Time: ${results.summary.maxResponseTime.toFixed(2)}ms`);
    console.log('\n📋 Production Readiness:');

    const assessment = tester.getProductionReadinessAssessment(results);
    console.log(assessment);

    console.log('\n📄 Detailed reports saved:');
    console.log(`   📝 ${reportPath}`);
    console.log(`   📊 ${jsonPath}`);

    if (results.summary.recommendations.length > 0) {
      console.log('\n💡 Key Recommendations:');
      results.summary.recommendations.slice(0, 5).forEach((rec) => {
        console.log(`   • ${rec}`);
      });
    }

    // Cleanup
    await tester.cleanup();

    // Exit with appropriate code
    const isProductionReady = assessment.includes('PRODUCTION READY');
    process.exit(isProductionReady ? 0 : 1);
  } catch (error) {
    logger.error({ error }, 'Test execution failed');
    console.error('\n❌ Test execution failed:', error instanceof Error ? error.message : error);
    await tester.cleanup();
    process.exit(1);
  }
}

// Handle unhandled rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error({ reason, promise }, 'Unhandled rejection in test runner');
  console.error('❌ Unhandled rejection:', reason);
  process.exit(1);
});

process.on('uncaughtException', (error) => {
  logger.error({ error }, 'Uncaught exception in test runner');
  console.error('❌ Uncaught exception:', error);
  process.exit(1);
});

// Run the tests
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
