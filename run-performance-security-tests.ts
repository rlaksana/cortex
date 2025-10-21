#!/usr/bin/env node

/**
 * Performance & Security Test Runner
 *
 * Simple script to run the integration tests and generate reports
 */

import { PerformanceSecurityIntegrationTest } from './tests/integration/performance-security-integration.test.js';
import { writeFileSync } from 'fs';
import { logger } from './src/utils/logger.js';

async function main() {
  console.log('🚀 Cortex MCP Performance & Security Integration Tests');
  console.log('=====================================================');

  const tester = new PerformanceSecurityIntegrationTest();
  const startTime = Date.now();

  try {
    // Run integration tests
    const results = await tester.runIntegrationTests();

    // Generate report
    const report = tester.generateAssessmentReport(results);

    // Save report
    const reportPath = 'PERFORMANCE_SECURITY_INTEGRATION_REPORT.md';
    writeFileSync(reportPath, report);

    // Save raw results
    const jsonPath = 'integration-test-results.json';
    writeFileSync(jsonPath, JSON.stringify(results, null, 2));

    const totalTime = Date.now() - startTime;

    // Print summary
    console.log('\n' + '='.repeat(60));
    console.log('📊 INTEGRATION TEST RESULTS');
    console.log('='.repeat(60));
    console.log(`⏱️  Total Test Time: ${(totalTime / 1000).toFixed(2)}s`);
    console.log(`🔧 Performance Tests: ${results.summary.totalPerformanceTests}`);
    console.log(`✅ Successful: ${results.summary.successfulPerformanceTests}`);
    console.log(`⚡ Avg Response Time: ${results.summary.avgResponseTime.toFixed(2)}ms`);
    console.log(`📈 Max Response Time: ${results.summary.maxResponseTime.toFixed(2)}ms`);
    console.log(`🔒 Security Tests: ${results.summary.totalSecurityTests}`);
    console.log(`🛡️  Blocked Attacks: ${results.summary.blockedSecurityTests}`);
    console.log(`⚠️  Vulnerabilities: ${results.summary.vulnerabilities}`);

    // Production readiness
    const isProductionReady = results.summary.avgResponseTime < 50 &&
                             results.summary.maxResponseTime < 500 &&
                             results.summary.vulnerabilities === 0 &&
                             (results.summary.successfulPerformanceTests / results.summary.totalPerformanceTests) >= 0.95;

    console.log(`\n🎯 Production Readiness: ${isProductionReady ? '✅ READY' : '❌ NOT READY'}`);

    console.log('\n📄 Reports saved:');
    console.log(`   📝 ${reportPath}`);
    console.log(`   📊 ${jsonPath}`);

    // Cleanup
    await tester.cleanup();

    process.exit(isProductionReady ? 0 : 1);

  } catch (error) {
    console.error('\n❌ Test execution failed:', error);
    await tester.cleanup();
    process.exit(1);
  }
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}