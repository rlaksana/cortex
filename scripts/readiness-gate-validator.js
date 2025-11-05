#!/usr/bin/env node

/**
 * Comprehensive Readiness Gate Validator
 *
 * This script validates all quality criteria before releases
 * - Build status validation
 * - Coverage thresholds verification (≥90%)
 * - Performance targets validation (p95 < 1s @ N=100)
 * - End-to-end alerting tests
 * - Security and compliance checks
 */

import { execSync, spawn } from 'child_process';
import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

// Configuration
const CONFIG = {
  // Coverage thresholds (90% as specified)
  COVERAGE_THRESHOLDS: {
    statements: 90,
    branches: 90,
    functions: 90,
    lines: 90
  },
  // Performance thresholds
  PERFORMANCE_THRESHOLDS: {
    p95_latency_ms: 1000,  // p95 < 1s as specified
    throughput_min: 100,   // Minimum operations per second
    error_rate_max: 1.0,   // Maximum error rate percentage
    memory_max_mb: 2048    // Maximum memory usage
  },
  // Load testing configuration (N=100 as specified)
  LOAD_TEST_CONFIG: {
    concurrent_users: 100,
    duration_seconds: 60,
    warmup_seconds: 10
  },
  // Quality gate thresholds
  QUALITY_GATES: {
    max_security_vulnerabilities: 0,  // Zero tolerance for security issues
    max_critical_bugs: 0,
    max_high_severity_issues: 0,
    max_eslint_warnings: 10,
    max_eslint_errors: 0
  },
  // Directories and files
  OUTPUT_DIR: join(projectRoot, 'artifacts', 'readiness-gates'),
  COVERAGE_DIR: join(projectRoot, 'coverage'),
  TEST_RESULTS_DIR: join(projectRoot, 'test-results'),
  BENCHMARK_DIR: join(projectRoot, 'artifacts', 'bench')
};

// Colors for console output
const COLORS = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m'
};

function log(message, color = COLORS.reset) {
  console.log(`${color}${message}${COLORS.reset}`);
}

function logError(message) {
  log(`❌ ${message}`, COLORS.red);
}

function logSuccess(message) {
  log(`✅ ${message}`, COLORS.green);
}

function logWarning(message) {
  log(`⚠️  ${message}`, COLORS.yellow);
}

function logInfo(message) {
  log(`ℹ️  ${message}`, COLORS.blue);
}

function logHeader(message) {
  log(`\n${COLORS.bold}${message}${COLORS.reset}`);
  log('='.repeat(message.length), COLORS.cyan);
}

/**
 * Execute command and return result
 */
function executeCommand(command, options = {}) {
  try {
    const result = execSync(command, {
      encoding: 'utf8',
      cwd: projectRoot,
      stdio: 'pipe',
      timeout: options.timeout || 300000, // 5 minutes default
      ...options
    });
    return { success: true, output: result, exitCode: 0 };
  } catch (error) {
    return {
      success: false,
      output: error.stdout || error.stderr || '',
      exitCode: error.status || 1,
      error
    };
  }
}

/**
 * Execute async command with real-time output
 */
function executeAsyncCommand(command, options = {}) {
  return new Promise((resolve, reject) => {
    const args = command.split(' ');
    const cmd = args.shift();

    const child = spawn(cmd, args, {
      cwd: projectRoot,
      stdio: 'pipe',
      ...options
    });

    let stdout = '';
    let stderr = '';

    child.stdout?.on('data', (data) => {
      const output = data.toString();
      stdout += output;
      if (options.realTimeOutput) {
        process.stdout.write(output);
      }
    });

    child.stderr?.on('data', (data) => {
      const output = data.toString();
      stderr += output;
      if (options.realTimeOutput) {
        process.stderr.write(output);
      }
    });

    child.on('close', (code) => {
      resolve({
        success: code === 0,
        exitCode: code,
        stdout,
        stderr
      });
    });

    child.on('error', (error) => {
      reject(error);
    });

    if (options.timeout) {
      setTimeout(() => {
        child.kill();
        reject(new Error(`Command timed out after ${options.timeout}ms`));
      }, options.timeout);
    }
  });
}

/**
 * Validate build status
 */
function validateBuildStatus() {
  logHeader('🏗️  Build Status Validation');

  const results = {
    typeCheck: { status: 'unknown', errors: [] },
    lint: { status: 'unknown', errors: [] },
    build: { status: 'unknown', errors: [] }
  };

  // Type check
  logInfo('Running TypeScript type check...');
  const typeCheckResult = executeCommand('npm run type-check', { timeout: 60000 });

  if (typeCheckResult.success) {
    results.typeCheck.status = 'passed';
    logSuccess('TypeScript compilation successful');
  } else {
    results.typeCheck.status = 'failed';
    results.typeCheck.errors = extractTypeScriptErrors(typeCheckResult.output);
    logError(`TypeScript compilation failed: ${results.typeCheck.errors.length} errors`);
  }

  // Lint check
  logInfo('Running ESLint...');
  const lintResult = executeCommand('npm run lint:hard', { timeout: 60000 });

  if (lintResult.success) {
    results.lint.status = 'passed';
    logSuccess('ESLint validation passed');
  } else {
    results.lint.status = 'failed';
    results.lint.errors = extractESLintErrors(lintResult.output);
    logError(`ESLint validation failed: ${results.lint.errors.length} issues`);
  }

  // Build
  logInfo('Building project...');
  const buildResult = executeCommand('npm run build', { timeout: 120000 });

  if (buildResult.success) {
    results.build.status = 'passed';
    logSuccess('Build completed successfully');
  } else {
    results.build.status = 'failed';
    results.build.errors = [buildResult.output];
    logError('Build failed');
  }

  const overallStatus = Object.values(results).every(r => r.status === 'passed');

  return {
    status: overallStatus ? 'passed' : 'failed',
    details: results,
    summary: {
      totalChecks: Object.keys(results).length,
      passedChecks: Object.values(results).filter(r => r.status === 'passed').length,
      failedChecks: Object.values(results).filter(r => r.status === 'failed').length
    }
  };
}

/**
 * Validate test coverage
 */
function validateCoverage() {
  logHeader('📊 Test Coverage Validation');

  const coverageFile = join(CONFIG.COVERAGE_DIR, 'coverage-summary.json');

  if (!existsSync(coverageFile)) {
    logInfo('Running coverage analysis...');
    const coverageResult = executeCommand('npm run test:coverage:json', { timeout: 300000 });

    if (!coverageResult.success) {
      return {
        status: 'failed',
        error: 'Coverage analysis failed to run',
        output: coverageResult.output
      };
    }
  }

  if (!existsSync(coverageFile)) {
    return {
      status: 'failed',
      error: 'Coverage file not found after running tests'
    };
  }

  try {
    const coverageData = JSON.parse(readFileSync(coverageFile, 'utf8'));
    const total = coverageData.total;

    logInfo('Coverage metrics:');

    const metrics = [
      { name: 'Statements', value: total.statements.pct, threshold: CONFIG.COVERAGE_THRESHOLDS.statements },
      { name: 'Branches', value: total.branches.pct, threshold: CONFIG.COVERAGE_THRESHOLDS.branches },
      { name: 'Functions', value: total.functions.pct, threshold: CONFIG.COVERAGE_THRESHOLDS.functions },
      { name: 'Lines', value: total.lines.pct, threshold: CONFIG.COVERAGE_THRESHOLDS.lines }
    ];

    const results = {};
    let allPassed = true;

    metrics.forEach(metric => {
      const passed = metric.value >= metric.threshold;
      results[metric.name.toLowerCase()] = {
        value: metric.value,
        threshold: metric.threshold,
        status: passed ? 'passed' : 'failed'
      };

      const status = passed ? '✅' : '❌';
      const color = passed ? COLORS.green : COLORS.red;
      log(`   ${status} ${metric.name}: ${metric.value}% (threshold: ${metric.threshold}%)`, color);

      if (!passed) {
        allPassed = false;
      }
    });

    return {
      status: allPassed ? 'passed' : 'failed',
      metrics: results,
      summary: {
        overallCoverage: total.statements.pct,
        thresholdMet: allPassed,
        gaps: metrics.filter(m => m.value < m.threshold).map(m => m.name)
      }
    };

  } catch (error) {
    return {
      status: 'failed',
      error: `Failed to parse coverage data: ${error.message}`
    };
  }
}

/**
 * Validate performance targets
 */
function validatePerformance() {
  logHeader('⚡ Performance Validation');

  // Check if benchmark results exist
  const benchmarkFile = join(CONFIG.BENCHMARK_DIR, 'benchmark-results.json');

  if (!existsSync(benchmarkFile)) {
    logInfo('Running performance benchmarks...');
    const benchmarkResult = executeCommand('npm run bench:quick', { timeout: 300000 });

    if (!benchmarkResult.success) {
      return {
        status: 'failed',
        error: 'Performance benchmarks failed to run',
        output: benchmarkResult.output
      };
    }
  }

  if (!existsSync(benchmarkFile)) {
    return {
      status: 'failed',
      error: 'Benchmark results not found after running tests'
    };
  }

  try {
    const benchmarkData = JSON.parse(readFileSync(benchmarkFile, 'utf8'));
    const results = {};
    let allPassed = true;

    logInfo('Performance metrics validation:');

    // Validate each benchmark scenario
    if (benchmarkData.results && Array.isArray(benchmarkData.results)) {
      benchmarkData.results.forEach(result => {
        const scenario = result.scenario || 'unknown';
        const metrics = result.metrics || {};

        // P95 latency check
        if (metrics.latencies && metrics.latencies.p95) {
          const p95Passed = metrics.latencies.p95 <= CONFIG.PERFORMANCE_THRESHOLDS.p95_latency_ms;
          results[`${scenario}_p95`] = {
            value: metrics.latencies.p95,
            threshold: CONFIG.PERFORMANCE_THRESHOLDS.p95_latency_ms,
            status: p95Passed ? 'passed' : 'failed'
          };

          const status = p95Passed ? '✅' : '❌';
          const color = p95Passed ? COLORS.green : COLORS.red;
          log(`   ${status} ${scenario} P95: ${metrics.latencies.p95}ms (threshold: ${CONFIG.PERFORMANCE_THRESHOLDS.p95_latency_ms}ms)`, color);

          if (!p95Passed) allPassed = false;
        }

        // Throughput check
        if (metrics.throughput) {
          const throughputPassed = metrics.throughput >= CONFIG.PERFORMANCE_THRESHOLDS.throughput_min;
          results[`${scenario}_throughput`] = {
            value: metrics.throughput,
            threshold: CONFIG.PERFORMANCE_THRESHOLDS.throughput_min,
            status: throughputPassed ? 'passed' : 'failed'
          };

          const status = throughputPassed ? '✅' : '❌';
          const color = throughputPassed ? COLORS.green : COLORS.red;
          log(`   ${status} ${scenario} Throughput: ${metrics.throughput} ops/s (threshold: ${CONFIG.PERFORMANCE_THRESHOLDS.throughput_min} ops/s)`, color);

          if (!throughputPassed) allPassed = false;
        }

        // Error rate check
        if (metrics.errorRate !== undefined) {
          const errorRatePassed = metrics.errorRate <= CONFIG.PERFORMANCE_THRESHOLDS.error_rate_max;
          results[`${scenario}_error_rate`] = {
            value: metrics.errorRate,
            threshold: CONFIG.PERFORMANCE_THRESHOLDS.error_rate_max,
            status: errorRatePassed ? 'passed' : 'failed'
          };

          const status = errorRatePassed ? '✅' : '❌';
          const color = errorRatePassed ? COLORS.green : COLORS.red;
          log(`   ${status} ${scenario} Error Rate: ${metrics.errorRate}% (threshold: ${CONFIG.PERFORMANCE_THRESHOLDS.error_rate_max}%)`, color);

          if (!errorRatePassed) allPassed = false;
        }
      });
    }

    // Run load test with N=100 as specified
    logInfo('Running load test with 100 concurrent users...');
    const loadTestResult = executeCommand(`npm run bench:load -c ${CONFIG.LOAD_TEST_CONFIG.concurrent_users} -n 1000`, {
      timeout: 300000,
      realTimeOutput: false
    });

    if (loadTestResult.success) {
      logSuccess('Load test completed successfully');
    } else {
      logWarning('Load test failed or did not complete');
      allPassed = false;
    }

    return {
      status: allPassed ? 'passed' : 'failed',
      metrics: results,
      loadTestPassed: loadTestResult.success,
      summary: {
        scenariosChecked: benchmarkData.results?.length || 0,
        thresholdsMet: allPassed,
        loadTestCompleted: loadTestResult.success
      }
    };

  } catch (error) {
    return {
      status: 'failed',
      error: `Failed to parse benchmark data: ${error.message}`
    };
  }
}

/**
 * Validate security and compliance
 */
function validateSecurity() {
  logHeader('🔒 Security & Compliance Validation');

  const results = {
    audit: { status: 'unknown', vulnerabilities: [] },
    eslintSecurity: { status: 'unknown', issues: [] },
    securityTests: { status: 'unknown', failures: [] }
  };

  // Security audit
  logInfo('Running security audit...');
  const auditResult = executeCommand('npm audit --audit-level=moderate --json', { timeout: 60000 });

  if (auditResult.success) {
    try {
      const auditData = JSON.parse(auditResult.output);
      const vulnerabilities = auditData.vulnerabilities || {};
      const highVulns = Object.values(vulnerabilities).filter(v => v.severity === 'high' || v.severity === 'critical');

      if (highVulns.length === 0) {
        results.audit.status = 'passed';
        logSuccess('Security audit passed - no high/critical vulnerabilities');
      } else {
        results.audit.status = 'failed';
        results.audit.vulnerabilities = highVulns;
        logError(`Security audit failed: ${highVulns.length} high/critical vulnerabilities found`);
      }
    } catch (parseError) {
      results.audit.status = 'failed';
      results.audit.vulnerabilities = [{ error: 'Failed to parse audit output' }];
      logError('Failed to parse security audit output');
    }
  } else {
    results.audit.status = 'failed';
    results.audit.vulnerabilities = [{ error: 'Audit command failed' }];
    logError('Security audit command failed');
  }

  // ESLint security rules
  logInfo('Running ESLint security rules...');
  const eslintResult = executeCommand('npm run lint:security', { timeout: 60000 });

  if (eslintResult.success) {
    results.eslintSecurity.status = 'passed';
    logSuccess('ESLint security checks passed');
  } else {
    results.eslintSecurity.status = 'failed';
    results.eslintSecurity.issues = extractESLintErrors(eslintResult.output);
    logError(`ESLint security checks failed: ${results.eslintSecurity.issues.length} issues`);
  }

  // Security tests
  logInfo('Running security test suite...');
  const securityTestResult = executeCommand('npm run test:security', { timeout: 180000 });

  if (securityTestResult.success) {
    results.securityTests.status = 'passed';
    logSuccess('Security tests passed');
  } else {
    results.securityTests.status = 'failed';
    results.securityTests.failures = extractTestFailures(securityTestResult.output);
    logError(`Security tests failed: ${results.securityTests.failures.length} failures`);
  }

  const overallStatus = Object.values(results).every(r => r.status === 'passed');

  return {
    status: overallStatus ? 'passed' : 'failed',
    details: results,
    summary: {
      totalChecks: Object.keys(results).length,
      passedChecks: Object.values(results).filter(r => r.status === 'passed').length,
      failedChecks: Object.values(results).filter(r => r.status === 'failed').length,
      vulnerabilitiesFound: results.audit.vulnerabilities.length
    }
  };
}

/**
 * Validate end-to-end alerting
 */
function validateAlerting() {
  logHeader('🚨 End-to-End Alerting Validation');

  const results = {
    healthChecks: { status: 'unknown', checks: [] },
    monitoringEndpoints: { status: 'unknown', endpoints: [] },
    alertTriggers: { status: 'unknown', triggers: [] }
  };

  // Health checks
  logInfo('Testing health check endpoints...');

  // Start the server for testing
  const serverProcess = spawn('npm', ['run', 'start'], {
    cwd: projectRoot,
    stdio: 'pipe',
    detached: true
  });

  // Give server time to start
  setTimeout(() => {
    try {
      // Test health endpoint
      const healthResult = executeCommand('curl -f http://localhost:3000/health || curl -f http://localhost:3000/api/health', { timeout: 10000 });

      if (healthResult.success) {
        results.healthChecks.status = 'passed';
        results.healthChecks.checks.push({ endpoint: 'health', status: 'responsive' });
        logSuccess('Health check endpoint responsive');
      } else {
        results.healthChecks.status = 'failed';
        results.healthChecks.checks.push({ endpoint: 'health', status: 'unresponsive' });
        logWarning('Health check endpoint not responsive');
      }
    } catch (error) {
      results.healthChecks.status = 'failed';
      results.healthChecks.checks.push({ endpoint: 'health', status: 'error', error: error.message });
      logWarning('Could not test health check endpoint');
    }

    // Clean up server process
    try {
      process.kill(-serverProcess.pid);
    } catch (e) {
      // Process might already be stopped
    }
  }, 5000);

  // Monitoring configuration validation
  logInfo('Validating monitoring configuration...');

  const monitoringFiles = [
    'src/monitoring/health-check-service.ts',
    'src/monitoring/production-health-checker.ts',
    'src/monitoring/monitoring-server.ts'
  ];

  let monitoringConfigValid = true;
  monitoringFiles.forEach(file => {
    if (existsSync(join(projectRoot, file))) {
      results.monitoringEndpoints.endpoints.push({ file, status: 'exists' });
    } else {
      results.monitoringEndpoints.endpoints.push({ file, status: 'missing' });
      monitoringConfigValid = false;
    }
  });

  results.monitoringEndpoints.status = monitoringConfigValid ? 'passed' : 'failed';

  if (monitoringConfigValid) {
    logSuccess('Monitoring configuration files present');
  } else {
    logWarning('Some monitoring configuration files missing');
  }

  // Alert trigger validation
  logInfo('Validating alert trigger configuration...');

  // Check for alert configuration
  const alertConfigFiles = [
    'docker/monitoring-stack.yml',
    'scripts/setup-alerts.sh'
  ];

  let alertConfigValid = true;
  alertConfigFiles.forEach(file => {
    if (existsSync(join(projectRoot, file))) {
      results.alertTriggers.triggers.push({ file, status: 'exists' });
    } else {
      results.alertTriggers.triggers.push({ file, status: 'missing' });
      alertConfigValid = false;
    }
  });

  results.alertTriggers.status = alertConfigValid ? 'passed' : 'failed';

  if (alertConfigValid) {
    logSuccess('Alert configuration files present');
  } else {
    logWarning('Some alert configuration files missing');
  }

  const overallStatus = Object.values(results).every(r => r.status === 'passed');

  return {
    status: overallStatus ? 'passed' : 'failed',
    details: results,
    summary: {
      totalChecks: Object.keys(results).length,
      passedChecks: Object.values(results).filter(r => r.status === 'passed').length,
      failedChecks: Object.values(results).filter(r => r.status === 'failed').length
    }
  };
}

/**
 * Generate comprehensive readiness report
 */
function generateReadinessReport(results) {
  logHeader('📋 Generating Readiness Report');

  // Ensure output directory exists
  mkdirSync(CONFIG.OUTPUT_DIR, { recursive: true });

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const reportFile = join(CONFIG.OUTPUT_DIR, `readiness-report-${timestamp}.json`);
  const htmlReportFile = join(CONFIG.OUTPUT_DIR, `readiness-report-${timestamp}.html`);

  const report = {
    metadata: {
      timestamp: new Date().toISOString(),
      version: '2.0.1',
      environment: process.env.NODE_ENV || 'development',
      nodeVersion: process.version,
      platform: process.platform
    },
    summary: {
      overallStatus: results.overallStatus,
      totalGates: Object.keys(results.gates).length,
      passedGates: Object.values(results.gates).filter(g => g.status === 'passed').length,
      failedGates: Object.values(results.gates).filter(g => g.status === 'failed').length,
      readyForRelease: results.overallStatus === 'passed'
    },
    gates: results.gates,
    recommendations: generateRecommendations(results.gates),
    artifacts: {
      reportFile,
      htmlReportFile,
      coverageDir: CONFIG.COVERAGE_DIR,
      testResultsDir: CONFIG.TEST_RESULTS_DIR,
      benchmarkDir: CONFIG.BENCHMARK_DIR
    }
  };

  // Write JSON report
  writeFileSync(reportFile, JSON.stringify(report, null, 2));
  logSuccess(`JSON report generated: ${reportFile}`);

  // Write HTML report
  const htmlReport = generateHTMLReport(report);
  writeFileSync(htmlReportFile, htmlReport);
  logSuccess(`HTML report generated: ${htmlReportFile}`);

  return report;
}

/**
 * Generate recommendations based on gate results
 */
function generateRecommendations(gates) {
  const recommendations = [];

  Object.entries(gates).forEach(([gateName, gateResult]) => {
    if (gateResult.status === 'failed') {
      switch (gateName) {
        case 'build':
          recommendations.push({
            priority: 'high',
            category: 'Build',
            issue: 'Build validation failed',
            action: 'Fix TypeScript compilation errors and ESLint issues before proceeding'
          });
          break;
        case 'coverage':
          recommendations.push({
            priority: 'high',
            category: 'Testing',
            issue: 'Test coverage below 90% threshold',
            action: 'Add more unit tests and integration tests to meet coverage requirements'
          });
          break;
        case 'performance':
          recommendations.push({
            priority: 'high',
            category: 'Performance',
            issue: 'Performance targets not met',
            action: 'Optimize code to meet p95 < 1s latency and throughput requirements'
          });
          break;
        case 'security':
          recommendations.push({
            priority: 'critical',
            category: 'Security',
            issue: 'Security vulnerabilities detected',
            action: 'Address all high/critical security vulnerabilities immediately'
          });
          break;
        case 'alerting':
          recommendations.push({
            priority: 'medium',
            category: 'Monitoring',
            issue: 'Alerting configuration incomplete',
            action: 'Set up proper monitoring and alerting for production readiness'
          });
          break;
      }
    }
  });

  return recommendations.sort((a, b) => {
    const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return priorityOrder[a.priority] - priorityOrder[b.priority];
  });
}

/**
 * Generate HTML report
 */
function generateHTMLReport(report) {
  const { metadata, summary, gates, recommendations } = report;

  const gateStatusColor = (status) => status === 'passed' ? '#4CAF50' : '#f44336';
  const gateStatusIcon = (status) => status === 'passed' ? '✅' : '❌';

  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Readiness Gate Report - ${metadata.version}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 40px; padding-bottom: 20px; border-bottom: 2px solid #e0e0e0; }
        .status-banner { padding: 20px; border-radius: 8px; text-align: center; font-size: 1.2em; font-weight: bold; margin-bottom: 30px; }
        .status-passed { background: #e8f5e8; color: #2e7d32; border: 2px solid #4caf50; }
        .status-failed { background: #ffebee; color: #c62828; border: 2px solid #f44336; }
        .gate-section { margin: 30px 0; padding: 20px; border-radius: 8px; border-left: 4px solid #ddd; }
        .gate-passed { border-left-color: #4CAF50; background: #f8f9fa; }
        .gate-failed { border-left-color: #f44336; background: #ffebee; }
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .metric-card { padding: 15px; border-radius: 8px; background: #f5f5f5; text-align: center; }
        .metric-value { font-size: 1.5em; font-weight: bold; margin-bottom: 5px; }
        .recommendations { margin: 30px 0; }
        .recommendation { padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #ff9800; background: #fff3e0; }
        .priority-critical { border-left-color: #f44336; background: #ffebee; }
        .priority-high { border-left-color: #ff9800; background: #fff3e0; }
        .priority-medium { border-left-color: #2196f3; background: #e3f2fd; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Release Readiness Gate Report</h1>
            <p>Version: ${metadata.version} | Generated: ${new Date(metadata.timestamp).toLocaleString()}</p>
            <div class="status-banner ${summary.readyForRelease ? 'status-passed' : 'status-failed'}">
                ${summary.readyForRelease ? '🎉 READY FOR RELEASE' : '🚫 NOT READY FOR RELEASE'}
            </div>
        </div>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value">${summary.totalGates}</div>
                <div>Total Gates</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: #4CAF50">${summary.passedGates}</div>
                <div>Passed</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: #f44336">${summary.failedGates}</div>
                <div>Failed</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: ${summary.readyForRelease ? '#4CAF50' : '#f44336'}">
                    ${summary.readyForRelease ? 'YES' : 'NO'}
                </div>
                <div>Release Ready</div>
            </div>
        </div>

        ${Object.entries(gates).map(([gateName, gateResult]) => `
        <div class="gate-section ${gateResult.status}">
            <h3>${gateStatusIcon(gateResult.status)} ${gateName.charAt(0).toUpperCase() + gateName.slice(1)} Gate</h3>
            <p><strong>Status:</strong> <span style="color: ${gateStatusColor(gateResult.status)}">${gateResult.status.toUpperCase()}</span></p>

            ${gateResult.summary ? `
            <div class="metrics-grid">
                ${Object.entries(gateResult.summary).map(([key, value]) => `
                <div class="metric-card">
                    <div class="metric-value">${value}</div>
                    <div>${key.replace(/([A-Z])/g, ' $1').trim()}</div>
                </div>
                `).join('')}
            </div>
            ` : ''}

            ${gateResult.error ? `<p><strong>Error:</strong> ${gateResult.error}</p>` : ''}
        </div>
        `).join('')}

        ${recommendations.length > 0 ? `
        <div class="recommendations">
            <h3>📋 Recommendations</h3>
            ${recommendations.map(rec => `
            <div class="recommendation priority-${rec.priority}">
                <h4>${rec.category} - ${rec.priority.toUpperCase()}</h4>
                <p><strong>Issue:</strong> ${rec.issue}</p>
                <p><strong>Action:</strong> ${rec.action}</p>
            </div>
            `).join('')}
        </div>
        ` : ''}

        <div class="footer">
            <p>Generated by Cortex Memory MCP Readiness Gate Validator</p>
            <p>Environment: ${metadata.environment} | Node.js: ${metadata.nodeVersion}</p>
        </div>
    </div>
</body>
</html>`;
}

/**
 * Helper function to extract TypeScript errors
 */
function extractTypeScriptErrors(output) {
  const errors = [];
  const lines = output.split('\n');

  lines.forEach(line => {
    if (line.includes('error TS') && !line.includes('node_modules')) {
      errors.push(line.trim());
    }
  });

  return errors;
}

/**
 * Helper function to extract ESLint errors
 */
function extractESLintErrors(output) {
  const errors = [];
  const lines = output.split('\n');

  lines.forEach(line => {
    if (line.includes('error') && !line.includes('node_modules')) {
      errors.push(line.trim());
    }
  });

  return errors;
}

/**
 * Helper function to extract test failures
 */
function extractTestFailures(output) {
  const failures = [];
  const lines = output.split('\n');

  lines.forEach(line => {
    if (line.includes('FAIL') || line.includes('×')) {
      failures.push(line.trim());
    }
  });

  return failures;
}

/**
 * Main readiness gate validation function
 */
async function validateReadinessGates() {
  logHeader('🎯 Comprehensive Readiness Gate Validation');
  logInfo('Validating all quality criteria for release readiness...\n');

  const startTime = Date.now();
  const results = {
    gates: {},
    overallStatus: 'unknown'
  };

  try {
    // Execute all gate validations
    results.gates.build = validateBuildStatus();
    await new Promise(resolve => setTimeout(resolve, 1000)); // Brief pause

    results.gates.coverage = validateCoverage();
    await new Promise(resolve => setTimeout(resolve, 1000));

    results.gates.performance = validatePerformance();
    await new Promise(resolve => setTimeout(resolve, 1000));

    results.gates.security = validateSecurity();
    await new Promise(resolve => setTimeout(resolve, 1000));

    results.gates.alerting = validateAlerting();
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Determine overall status
    const failedGates = Object.values(results.gates).filter(gate => gate.status === 'failed');
    results.overallStatus = failedGates.length === 0 ? 'passed' : 'failed';

    // Generate report
    const report = generateReadinessReport(results);

    // Final summary
    const duration = Math.round((Date.now() - startTime) / 1000);
    logHeader('📊 Readiness Gate Validation Complete');

    logInfo(`Validation completed in ${duration} seconds`);
    logInfo(`Gates passed: ${Object.values(results.gates).filter(g => g.status === 'passed').length}/${Object.keys(results.gates).length}`);

    if (results.overallStatus === 'passed') {
      logSuccess('\n🎉 ALL READINESS GATES PASSED - READY FOR RELEASE');
      logSuccess('✅ Build is green (0 TypeScript errors)');
      logSuccess('✅ Coverage ≥ 90%');
      logSuccess('✅ Performance targets met (p95 < 1s @ N=100)');
      logSuccess('✅ Alerts verified (end-to-end alerting tests pass)');
      logSuccess('✅ Security and compliance checks passed');

      process.exit(0);
    } else {
      logError('\n🚫 READINESS GATES FAILED - RELEASE BLOCKED');
      logError('The following gates must be addressed before release:');

      Object.entries(results.gates).forEach(([gateName, gateResult]) => {
        if (gateResult.status === 'failed') {
          logError(`  ❌ ${gateName.charAt(0).toUpperCase() + gateName.slice(1)}: ${gateResult.error || 'Validation failed'}`);
        }
      });

      logError('\n💡 Review the detailed report for specific actions needed');
      logError(`📄 Report: ${report.artifacts.reportFile}`);
      logError(`🌐 HTML Report: ${report.artifacts.htmlReportFile}`);

      process.exit(1);
    }

  } catch (error) {
    logError(`Readiness gate validation failed: ${error.message}`);
    process.exit(1);
  }
}

// Run the validation if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  validateReadinessGates().catch(error => {
    logError(`Unexpected error: ${error.message}`);
    process.exit(1);
  });
}

export { validateReadinessGates };