#!/usr/bin/env node

/**
 * Performance CI Gate Script
 *
 * CI pipeline integration script that runs performance tests,
 * checks for regressions, and enforces performance gates
 */

import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { readFileSync, existsSync } from 'fs';
import { PerformanceHarness } from '../src/performance/performance-harness.js';
import { PerformanceArtifactStorage } from '../src/performance/artifact-storage.js';
import { CIRegressionGuard } from '../src/performance/ci-regression-guard.js';
import { PERFORMANCE_TEST_CONFIGS } from '../src/performance/performance-targets.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Parse command line arguments
const args = process.argv.slice(2);
const options = {
  testSuite: 'all',
  outputDir: './artifacts/performance',
  failOnRegression: true,
  updateBaseline: false,
  verbose: false,
  config: null,
};

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  switch (arg) {
    case '--test-suite':
      options.testSuite = args[++i];
      break;
    case '--output-dir':
      options.outputDir = args[++i];
      break;
    case '--no-fail-on-regression':
      options.failOnRegression = false;
      break;
    case '--update-baseline':
      options.updateBaseline = true;
      break;
    case '--verbose':
      options.verbose = true;
      break;
    case '--config':
      options.config = args[++i];
      break;
    case '--help':
      console.log(`
Performance CI Gate

Usage: node performance-ci-gate.js [options]

Options:
  --test-suite <name>     Run specific test suite (default: all)
  --output-dir <path>     Output directory for artifacts (default: ./artifacts/performance)
  --no-fail-on-regression Don't fail the CI pipeline on regressions
  --update-baseline       Update baseline with new results
  --verbose               Enable verbose logging
  --config <path>         Path to configuration file
  --help                  Show this help message

Test Suites:
  all                     Run all performance tests
  storage                 Knowledge storage tests
  search                   Search and retrieval tests
  circuit-breaker         Circuit breaker tests
  health-check            Health check tests
  critical                Critical path tests only

Exit Codes:
  0                       All tests passed
  1                       Performance regressions detected
  2                       Test execution failed
  3                       Invalid configuration
`);
      process.exit(0);
  }
}

async function main() {
  const startTime = Date.now();

  console.log('🚀 Starting Performance CI Gate');
  console.log(`📊 Test Suite: ${options.testSuite}`);
  console.log(`📁 Output Directory: ${options.outputDir}`);
  console.log(`⚡ Fail on Regression: ${options.failOnRegression}`);
  console.log('');

  try {
    // Load custom configuration if provided
    let config = {};
    if (options.config && existsSync(options.config)) {
      const configContent = readFileSync(options.config, 'utf-8');
      config = JSON.parse(configContent);
      console.log(`✅ Configuration loaded from: ${options.config}`);
    }

    // Initialize components
    const harness = new PerformanceHarness(
      join(options.outputDir, 'test-results'),
      join(options.outputDir, 'baseline')
    );

    const storage = new PerformanceArtifactStorage({
      baseDir: options.outputDir,
      maxArtifacts: 100,
      retentionDays: 30,
    });

    const regressionGuard = new CIRegressionGuard({
      baselineDir: join(options.outputDir, 'baseline'),
      reportsDir: join(options.outputDir, 'regression-reports'),
      performanceGateEnabled: options.failOnRegression,
      autoUpdateBaseline: options.updateBaseline,
      ...config,
    });

    // Determine which tests to run
    const testConfigs = getTestConfigs(options.testSuite);
    console.log(`📋 Running ${testConfigs.length} test configurations`);
    console.log('');

    // Run performance tests
    console.log('🏃‍♂️ Running Performance Tests...');
    const results = await harness.runTestSuite(testConfigs);

    if (options.verbose) {
      for (const result of results) {
        console.log(`  ${result.config.name}: ${result.validation.passed ? '✅ PASS' : '❌ FAIL'}`);
        console.log(`    p95: ${result.results.metrics.latencies.p95.toFixed(1)}ms`);
        console.log(`    p99: ${result.results.metrics.latencies.p99.toFixed(1)}ms`);
        console.log(`    Throughput: ${result.results.metrics.throughput.toFixed(1)} ops/s`);
        console.log(`    Error Rate: ${result.results.metrics.errorRate.toFixed(1)}%`);
      }
    }
    console.log('');

    // Store artifacts
    console.log('💾 Storing Performance Artifacts...');
    for (const result of results) {
      await storage.storeTestResults(result);
    }
    console.log('✅ Artifacts stored successfully');
    console.log('');

    // Check for regressions
    console.log('🔍 Checking for Performance Regressions...');
    const regressionReports = await regressionGuard.checkRegressions(results);

    const failedTests = regressionReports.filter((r) => !r.ciGateStatus.passed);
    const regressionDetected = regressionReports.some((r) => r.regressionDetected);

    // Display results
    console.log('📊 Test Results Summary:');
    console.log(`  Total Tests: ${results.length}`);
    console.log(`  Passed: ${results.length - failedTests.length}`);
    console.log(`  Failed: ${failedTests.length}`);
    console.log(`  Regressions: ${regressionReports.filter((r) => r.regressionDetected).length}`);
    console.log('');

    // Show detailed regression information
    if (failedTests.length > 0) {
      console.log('❌ Performance Regressions Detected:');
      for (const report of failedTests) {
        console.log(`  ${report.testName}: ${report.assessment.summary}`);
        if (options.verbose && report.regressions.length > 0) {
          for (const regression of report.regressions) {
            console.log(
              `    - ${regression.metric}: ${regression.current} (baseline: ${regression.baseline}, change: ${regression.changePercentage.toFixed(1)}%) [${regression.severity.toUpperCase()}]`
            );
          }
        }
      }
      console.log('');
    }

    // Get deployment gate status
    const gateStatus = regressionGuard.getDeploymentGateStatus(regressionReports);

    if (gateStatus.canDeploy) {
      console.log('✅ Performance Gate: PASSED');
      console.log('🚀 Ready for deployment');
    } else {
      console.log('❌ Performance Gate: FAILED');
      console.log(`🚫 Deployment blocked: ${gateStatus.reason}`);
      if (gateStatus.blockedTests.length > 0) {
        console.log('Blocked tests:', gateStatus.blockedTests.join(', '));
      }
    }
    console.log('');

    // Export CI results
    const ciResults = regressionGuard.exportCIResults(regressionReports);

    // Write CI results file
    const ciResultsPath = join(options.outputDir, 'ci-results.json');
    require('fs').writeFileSync(
      ciResultsPath,
      JSON.stringify(
        {
          summary: ciResults.summary,
          exitCode: ciResults.exitCode,
          metrics: ciResults.metrics,
          artifacts: ciResults.artifacts,
          gateStatus,
          duration: Date.now() - startTime,
          timestamp: new Date().toISOString(),
        },
        null,
        2
      )
    );

    console.log(`📄 CI results written to: ${ciResultsPath}`);
    console.log('');

    // Performance summary table
    console.log('📈 Performance Summary:');
    console.log(
      '┌─────────────────────────────────────────────────────────────────────────────────────┐'
    );
    console.log(
      '│ Test Name                              │ Status │ p95 (ms) │ p99 (ms) │ Throughput │'
    );
    console.log(
      '├─────────────────────────────────────────────────────────────────────────────────────┤'
    );

    for (const result of results) {
      const status = result.validation.passed ? '✅ PASS' : '❌ FAIL';
      const p95 = result.results.metrics.latencies.p95.toFixed(1).padStart(7);
      const p99 = result.results.metrics.latencies.p99.toFixed(1).padStart(7);
      const throughput = result.results.metrics.throughput.toFixed(1).padStart(9);
      const name = result.config.name.padEnd(38);

      console.log(`│ ${name} │ ${status} │ ${p95} │ ${p99} │ ${throughput} │`);
    }

    console.log(
      '└─────────────────────────────────────────────────────────────────────────────────────┘'
    );
    console.log('');

    // Exit with appropriate code
    if (ciResults.exitCode !== 0) {
      console.log(`💥 Performance CI Gate FAILED (exit code: ${ciResults.exitCode})`);
      process.exit(ciResults.exitCode);
    } else {
      console.log(`✅ Performance CI Gate PASSED (exit code: ${ciResults.exitCode})`);
      console.log(`⏱️  Total duration: ${((Date.now() - startTime) / 1000).toFixed(2)}s`);
      process.exit(0);
    }
  } catch (error) {
    console.error('💥 Performance CI Gate failed with error:');
    console.error(error);
    console.log('');
    console.log('This might be due to:');
    console.log('1. Missing dependencies or configuration');
    console.log('2. Network or database connectivity issues');
    console.log('3. Insufficient system resources');
    console.log('4. Test environment setup problems');
    console.log('');
    console.log('Please check the logs and try again.');
    process.exit(2);
  }
}

/**
 * Get test configurations based on test suite name
 */
function getTestConfigs(testSuite) {
  switch (testSuite) {
    case 'storage':
      return PERFORMANCE_TEST_CONFIGS.filter(
        (config) => config.categories.includes('storage') || config.categories.includes('knowledge')
      );

    case 'search':
      return PERFORMANCE_TEST_CONFIGS.filter(
        (config) => config.categories.includes('search') || config.categories.includes('retrieval')
      );

    case 'circuit-breaker':
      return PERFORMANCE_TEST_CONFIGS.filter(
        (config) =>
          config.categories.includes('circuit_breaker') || config.categories.includes('resilience')
      );

    case 'health-check':
      return PERFORMANCE_TEST_CONFIGS.filter(
        (config) => config.categories.includes('health') || config.categories.includes('monitoring')
      );

    case 'critical':
      return PERFORMANCE_TEST_CONFIGS.filter((config) => config.categories.includes('critical'));

    case 'all':
    default:
      return PERFORMANCE_TEST_CONFIGS;
  }
}

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  console.error('💥 Uncaught Exception:', error);
  process.exit(2);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(2);
});

// Run main function
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
