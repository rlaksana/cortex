#!/usr/bin/env node

/**
 * Quality Gate Enforcer
 *
 * Comprehensive quality gate enforcement system that:
 * - Blocks releases that don't meet quality standards
 * - Provides clear feedback on what needs to be fixed
 * - Validates code quality, security, performance, and compliance
 * - Integrates with CI/CD pipelines for automated enforcement
 */

import { execSync } from 'child_process';
import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

// Quality gate configuration
const CONFIG = {
  // Quality thresholds
  THRESHOLDS: {
    // Build quality
    TYPESCRIPT_ERRORS: 0,
    ESLINT_ERRORS: 0,
    ESLINT_WARNINGS: 10,

    // Test coverage (90% as specified)
    COVERAGE_STATEMENTS: 90,
    COVERAGE_BRANCHES: 90,
    COVERAGE_FUNCTIONS: 90,
    COVERAGE_LINES: 90,

    // Performance (p95 < 1s @ N=100)
    P95_LATENCY_MS: 1000,
    THROUGHPUT_MIN: 100,
    ERROR_RATE_MAX: 1.0,

    // Security
    SECURITY_VULNERABILITIES_CRITICAL: 0,
    SECURITY_VULNERABILITIES_HIGH: 0,
    SECURITY_VULNERABILITIES_MODERATE: 5,

    // Code quality
    CODE_DUPLICATION_MAX: 3, // percentage
    COMPLEXITY_MAX: 10,      // cyclomatic complexity
    FILE_SIZE_MAX_KB: 500,   // max file size
  },

  // Enforcement modes
  ENFORCEMENT: {
    STRICT: process.env.Quality_Gate_Strict === 'true',
    BLOCK_RELEASES: process.env.Quality_Gate_Block_Release !== 'false', // Default to true
    REQUIRE_ALL_GATES: process.env.Quality_Gate_All !== 'false', // Default to true
    WARN_ONLY: process.env.Quality_Gate_Warn_Only === 'true'
  },

  // Output configuration
  OUTPUT_DIR: join(projectRoot, 'artifacts', 'quality-gates'),
  REPORT_FORMATS: ['json', 'html', 'junit'],

  // Gate definitions
  GATES: [
    {
      name: 'build',
      description: 'Build and compilation quality',
      required: true,
      weight: 25
    },
    {
      name: 'coverage',
      description: 'Test coverage thresholds',
      required: true,
      weight: 25
    },
    {
      name: 'performance',
      description: 'Performance targets',
      required: true,
      weight: 25
    },
    {
      name: 'security',
      description: 'Security and vulnerability checks',
      required: true,
      weight: 25
    }
  ]
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
  bold: '\x1b[1m',
  inverse: '\x1b[7m'
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

function logCritical(message) {
  log(`🚫 ${message}`, COLORS.inverse, COLORS.red, COLORS.bold);
}

function logHeader(message) {
  log(`\n${COLORS.bold}${message}${COLORS.reset}`);
  log('='.repeat(message.length), COLORS.cyan);
}

/**
 * Execute command and capture result
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
 * Validate build quality gate
 */
function validateBuildGate() {
  logInfo('Validating build quality gate...');

  const gateResult = {
    name: 'build',
    status: 'unknown',
    score: 0,
    maxScore: CONFIG.GATES.find(g => g.name === 'build').weight,
    checks: {},
    issues: [],
    recommendations: []
  };

  // TypeScript compilation
  logInfo('  Checking TypeScript compilation...');
  const typeCheckResult = executeCommand('npm run type-check', { timeout: 60000 });

  if (typeCheckResult.success) {
    gateResult.checks.typescript = { status: 'passed', errors: 0 };
    gateResult.score += 10;
  } else {
    const errors = extractTypeScriptErrors(typeCheckResult.output);
    gateResult.checks.typescript = {
      status: 'failed',
      errors: errors.length,
      details: errors.slice(0, 5) // First 5 errors
    };
    gateResult.issues.push(`TypeScript compilation failed: ${errors.length} errors`);
    gateResult.recommendations.push('Fix all TypeScript compilation errors');
  }

  // ESLint quality check
  logInfo('  Running ESLint quality checks...');
  const lintResult = executeCommand('npm run lint:hard', { timeout: 60000 });

  if (lintResult.success) {
    gateResult.checks.eslint = { status: 'passed', errors: 0, warnings: 0 };
    gateResult.score += 10;
  } else {
    const { errors, warnings } = extractESLintIssues(lintResult.output);
    gateResult.checks.eslint = {
      status: 'failed',
      errors,
      warnings,
      details: { errors, warnings }
    };

    if (errors > 0) {
      gateResult.issues.push(`ESLint errors detected: ${errors}`);
      gateResult.recommendations.push('Fix all ESLint errors');
    }
    if (warnings > CONFIG.THRESHOLDS.ESLINT_WARNINGS) {
      gateResult.issues.push(`Too many ESLint warnings: ${warnings} (max: ${CONFIG.THRESHOLDS.ESLINT_WARNINGS})`);
      gateResult.recommendations.push('Reduce ESLint warnings below threshold');
    }

    // Partial score for warnings only
    if (errors === 0 && warnings <= CONFIG.THRESHOLDS.ESLINT_WARNINGS) {
      gateResult.score += 8;
    }
  }

  // Code formatting check
  logInfo('  Checking code formatting...');
  const formatResult = executeCommand('npm run format:check', { timeout: 30000 });

  if (formatResult.success) {
    gateResult.checks.formatting = { status: 'passed' };
    gateResult.score += 5;
  } else {
    gateResult.checks.formatting = { status: 'failed' };
    gateResult.issues.push('Code formatting issues detected');
    gateResult.recommendations.push('Run `npm run format` to fix formatting');
  }

  // Build process
  logInfo('  Running build process...');
  const buildResult = executeCommand('npm run build', { timeout: 120000 });

  if (buildResult.success) {
    gateResult.checks.build = { status: 'passed' };
    gateResult.score += 0; // Build is expected to work if TypeScript passed
  } else {
    gateResult.checks.build = { status: 'failed' };
    gateResult.issues.push('Build process failed');
    gateResult.recommendations.push('Fix build issues');
  }

  // Determine overall gate status
  const hasCriticalIssues = gateResult.checks.typescript.errors > 0 ||
                           gateResult.checks.eslint.errors > 0 ||
                           gateResult.checks.build.status === 'failed';

  gateResult.status = hasCriticalIssues ? 'failed' :
                     (gateResult.score >= gateResult.maxScore * 0.8 ? 'passed' : 'warning');

  logInfo(`  Build gate result: ${gateResult.status} (${gateResult.score}/${gateResult.maxScore})`);
  return gateResult;
}

/**
 * Validate coverage gate
 */
function validateCoverageGate() {
  logInfo('Validating coverage quality gate...');

  const gateResult = {
    name: 'coverage',
    status: 'unknown',
    score: 0,
    maxScore: CONFIG.GATES.find(g => g.name === 'coverage').weight,
    checks: {},
    issues: [],
    recommendations: []
  };

  // Run coverage if not available
  const coverageFile = join(projectRoot, 'coverage', 'coverage-summary.json');
  if (!existsSync(coverageFile)) {
    logInfo('  Running coverage analysis...');
    const coverageResult = executeCommand('npm run test:coverage:json', { timeout: 300000 });
    if (!coverageResult.success) {
      gateResult.checks.analysis = { status: 'failed', error: coverageResult.output };
      gateResult.issues.push('Coverage analysis failed to run');
      gateResult.recommendations.push('Fix test execution issues');
      gateResult.status = 'failed';
      return gateResult;
    }
  }

  // Parse coverage results
  if (!existsSync(coverageFile)) {
    gateResult.checks.analysis = { status: 'failed', error: 'Coverage file not found' };
    gateResult.issues.push('Coverage report not generated');
    gateResult.recommendations.push('Ensure tests generate coverage report');
    gateResult.status = 'failed';
    return gateResult;
  }

  try {
    const coverageData = JSON.parse(readFileSync(coverageFile, 'utf8'));
    const total = coverageData.total;

    // Check each coverage metric
    const metrics = [
      { name: 'statements', value: total.statements.pct, threshold: CONFIG.THRESHOLDS.COVERAGE_STATEMENTS },
      { name: 'branches', value: total.branches.pct, threshold: CONFIG.THRESHOLDS.COVERAGE_BRANCHES },
      { name: 'functions', value: total.functions.pct, threshold: CONFIG.THRESHOLDS.COVERAGE_FUNCTIONS },
      { name: 'lines', value: total.lines.pct, threshold: CONFIG.THRESHOLDS.COVERAGE_LINES }
    ];

    let totalScore = 0;
    metrics.forEach(metric => {
      const passed = metric.value >= metric.threshold;
      gateResult.checks[metric.name] = {
        status: passed ? 'passed' : 'failed',
        value: metric.value,
        threshold: metric.threshold,
        gap: Math.max(0, metric.threshold - metric.value)
      };

      if (passed) {
        totalScore += CONFIG.GATES.find(g => g.name === 'coverage').weight / 4;
      } else {
        gateResult.issues.push(`${metric.name} coverage: ${metric.value}% (required: ${metric.threshold}%)`);
        gateResult.recommendations.push(`Add tests to improve ${metric.name} coverage by ${gateResult.checks[metric.name].gap.toFixed(1)}%`);
      }
    });

    gateResult.score = totalScore;

    // Determine overall status
    const allPassed = metrics.every(m => m.value >= m.threshold);
    const averageCoverage = (total.statements.pct + total.branches.pct + total.functions.pct + total.lines.pct) / 4;

    gateResult.status = allPassed ? 'passed' :
                       (averageCoverage >= 85 ? 'warning' : 'failed');

    logInfo(`  Coverage gate result: ${gateResult.status} (${gateResult.score.toFixed(1)}/${gateResult.maxScore})`);

  } catch (error) {
    gateResult.checks.parsing = { status: 'failed', error: error.message };
    gateResult.issues.push('Failed to parse coverage data');
    gateResult.recommendations.push('Check coverage report format');
    gateResult.status = 'failed';
  }

  return gateResult;
}

/**
 * Validate performance gate
 */
function validatePerformanceGate() {
  logInfo('Validating performance quality gate...');

  const gateResult = {
    name: 'performance',
    status: 'unknown',
    score: 0,
    maxScore: CONFIG.GATES.find(g => g.name === 'performance').weight,
    checks: {},
    issues: [],
    recommendations: []
  };

  // Run performance validation if results don't exist
  const benchmarkFile = join(projectRoot, 'artifacts', 'bench', 'benchmark-results.json');
  if (!existsSync(benchmarkFile)) {
    logInfo('  Running performance benchmarks...');
    const benchmarkResult = executeCommand('npm run bench:quick', { timeout: 300000 });
    if (!benchmarkResult.success) {
      gateResult.checks.benchmarks = { status: 'failed', error: benchmarkResult.output };
      gateResult.issues.push('Performance benchmarks failed');
      gateResult.recommendations.push('Fix performance test execution');
      gateResult.status = 'failed';
      return gateResult;
    }
  }

  // Parse performance results
  if (!existsSync(benchmarkFile)) {
    gateResult.checks.analysis = { status: 'failed', error: 'Benchmark file not found' };
    gateResult.issues.push('Performance benchmark results not found');
    gateResult.recommendations.push('Ensure performance tests generate benchmark results');
    gateResult.status = 'failed';
    return gateResult;
  }

  try {
    const benchmarkData = JSON.parse(readFileSync(benchmarkFile, 'utf8'));

    if (!benchmarkData.results || !Array.isArray(benchmarkData.results)) {
      gateResult.checks.analysis = { status: 'failed', error: 'Invalid benchmark data format' };
      gateResult.status = 'failed';
      return gateResult;
    }

    // Aggregate performance metrics
    const avgP95 = benchmarkData.results.reduce((sum, r) => sum + (r.metrics?.latencies?.p95 || 0), 0) / benchmarkData.results.length;
    const avgThroughput = benchmarkData.results.reduce((sum, r) => sum + (r.metrics?.throughput || 0), 0) / benchmarkData.results.length;
    const avgErrorRate = benchmarkData.results.reduce((sum, r) => sum + (r.metrics?.errorRate || 0), 0) / benchmarkData.results.length;

    // Check P95 latency
    const p95Passed = avgP95 <= CONFIG.THRESHOLDS.P95_LATENCY_MS;
    gateResult.checks.p95Latency = {
      status: p95Passed ? 'passed' : 'failed',
      value: avgP95,
      threshold: CONFIG.THRESHOLDS.P95_LATENCY_MS,
      deviation: avgP95 - CONFIG.THRESHOLDS.P95_LATENCY_MS
    };

    if (p95Passed) {
      gateResult.score += 10;
    } else {
      gateResult.issues.push(`P95 latency: ${avgP95.toFixed(2)}ms (required: <${CONFIG.THRESHOLDS.P95_LATENCY_MS}ms)`);
      gateResult.recommendations.push('Optimize performance to meet P95 latency targets');
    }

    // Check throughput
    const throughputPassed = avgThroughput >= CONFIG.THRESHOLDS.THROUGHPUT_MIN;
    gateResult.checks.throughput = {
      status: throughputPassed ? 'passed' : 'failed',
      value: avgThroughput,
      threshold: CONFIG.THRESHOLDS.THROUGHPUT_MIN,
      gap: Math.max(0, CONFIG.THRESHOLDS.THROUGHPUT_MIN - avgThroughput)
    };

    if (throughputPassed) {
      gateResult.score += 10;
    } else {
      gateResult.issues.push(`Throughput: ${avgThroughput.toFixed(2)} ops/s (required: ≥${CONFIG.THRESHOLDS.THROUGHPUT_MIN} ops/s)`);
      gateResult.recommendations.push('Improve throughput to meet minimum requirements');
    }

    // Check error rate
    const errorRatePassed = avgErrorRate <= CONFIG.THRESHOLDS.ERROR_RATE_MAX;
    gateResult.checks.errorRate = {
      status: errorRatePassed ? 'passed' : 'failed',
      value: avgErrorRate,
      threshold: CONFIG.THRESHOLDS.ERROR_RATE_MAX,
      excess: Math.max(0, avgErrorRate - CONFIG.THRESHOLDS.ERROR_RATE_MAX)
    };

    if (errorRatePassed) {
      gateResult.score += 5;
    } else {
      gateResult.issues.push(`Error rate: ${avgErrorRate.toFixed(2)}% (required: <${CONFIG.THRESHOLDS.ERROR_RATE_MAX}%)`);
      gateResult.recommendations.push('Fix reliability issues to reduce error rate');
    }

    // Determine overall status
    const criticalIssues = !p95Passed || !errorRatePassed;
    gateResult.status = criticalIssues ? 'failed' :
                       (gateResult.score >= gateResult.maxScore * 0.8 ? 'passed' : 'warning');

    logInfo(`  Performance gate result: ${gateResult.status} (${gateResult.score}/${gateResult.maxScore})`);

  } catch (error) {
    gateResult.checks.parsing = { status: 'failed', error: error.message };
    gateResult.issues.push('Failed to parse performance data');
    gateResult.recommendations.push('Check performance benchmark format');
    gateResult.status = 'failed';
  }

  return gateResult;
}

/**
 * Validate security gate
 */
function validateSecurityGate() {
  logInfo('Validating security quality gate...');

  const gateResult = {
    name: 'security',
    status: 'unknown',
    score: 0,
    maxScore: CONFIG.GATES.find(g => g.name === 'security').weight,
    checks: {},
    issues: [],
    recommendations: []
  };

  // Security audit
  logInfo('  Running security audit...');
  const auditResult = executeCommand('npm audit --audit-level=moderate --json', { timeout: 60000 });

  if (auditResult.success) {
    try {
      const auditData = JSON.parse(auditResult.output);
      const vulnerabilities = auditData.vulnerabilities || {};

      const critical = Object.values(vulnerabilities).filter(v => v.severity === 'critical').length;
      const high = Object.values(vulnerabilities).filter(v => v.severity === 'high').length;
      const moderate = Object.values(vulnerabilities).filter(v => v.severity === 'moderate').length;
      const low = Object.values(vulnerabilities).filter(v => v.severity === 'low').length;

      gateResult.checks.audit = {
        status: 'passed',
        critical,
        high,
        moderate,
        low,
        total: Object.keys(vulnerabilities).length
      };

      // Score based on vulnerability levels
      if (critical === 0 && high === 0) {
        gateResult.score += 15;
        if (moderate <= CONFIG.THRESHOLDS.SECURITY_VULNERABILITIES_MODERATE) {
          gateResult.score += 5;
        }
      }

      // Check thresholds
      if (critical > 0) {
        gateResult.issues.push(`Critical vulnerabilities: ${critical} (required: 0)`);
        gateResult.recommendations.push('Address all critical security vulnerabilities immediately');
        gateResult.checks.audit.status = 'failed';
      }
      if (high > 0) {
        gateResult.issues.push(`High vulnerabilities: ${high} (required: 0)`);
        gateResult.recommendations.push('Address all high security vulnerabilities');
        gateResult.checks.audit.status = 'failed';
      }
      if (moderate > CONFIG.THRESHOLDS.SECURITY_VULNERABILITIES_MODERATE) {
        gateResult.issues.push(`Moderate vulnerabilities: ${moderate} (max: ${CONFIG.THRESHOLDS.SECURITY_VULNERABILITIES_MODERATE})`);
        gateResult.recommendations.push('Reduce moderate security vulnerabilities');
        if (gateResult.checks.audit.status === 'passed') {
          gateResult.checks.audit.status = 'warning';
        }
      }

    } catch (parseError) {
      gateResult.checks.audit = { status: 'failed', error: 'Failed to parse audit output' };
      gateResult.issues.push('Security audit output parsing failed');
      gateResult.recommendations.push('Check npm audit output format');
    }
  } else {
    gateResult.checks.audit = { status: 'failed', error: auditResult.output };
    gateResult.issues.push('Security audit command failed');
    gateResult.recommendations.push('Fix npm audit execution issues');
  }

  // ESLint security rules
  logInfo('  Running ESLint security checks...');
  const eslintResult = executeCommand('npm run lint:security', { timeout: 60000 });

  if (eslintResult.success) {
    gateResult.checks.eslintSecurity = { status: 'passed', issues: 0 };
    gateResult.score += 5;
  } else {
    const { errors, warnings } = extractESLintIssues(eslintResult.output);
    gateResult.checks.eslintSecurity = {
      status: 'failed',
      errors,
      warnings,
      total: errors + warnings
    };

    if (errors > 0) {
      gateResult.issues.push(`ESLint security errors: ${errors}`);
      gateResult.recommendations.push('Fix all ESLint security issues');
    }
    if (warnings > 0) {
      gateResult.issues.push(`ESLint security warnings: ${warnings}`);
      gateResult.recommendations.push('Address ESLint security warnings');
    }
  }

  // Security tests
  logInfo('  Running security tests...');
  const securityTestResult = executeCommand('npm run test:security', { timeout: 180000 });

  if (securityTestResult.success) {
    gateResult.checks.securityTests = { status: 'passed' };
    gateResult.score += 5;
  } else {
    gateResult.checks.securityTests = { status: 'failed' };
    gateResult.issues.push('Security tests failed');
    gateResult.recommendations.push('Fix failing security tests');
  }

  // Determine overall status
  const hasSecurityIssues = gateResult.checks.audit.status === 'failed' ||
                           gateResult.checks.eslintSecurity.errors > 0 ||
                           gateResult.checks.securityTests.status === 'failed';

  gateResult.status = hasSecurityIssues ? 'failed' :
                     (gateResult.checks.audit.status === 'warning' ? 'warning' : 'passed');

  logInfo(`  Security gate result: ${gateResult.status} (${gateResult.score}/${gateResult.maxScore})`);
  return gateResult;
}

/**
 * Extract TypeScript errors from output
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
 * Extract ESLint issues from output
 */
function extractESLintIssues(output) {
  let errors = 0;
  let warnings = 0;

  const lines = output.split('\n');
  lines.forEach(line => {
    if (line.includes('error') && !line.includes('node_modules')) {
      errors++;
    } else if (line.includes('warning') && !line.includes('node_modules')) {
      warnings++;
    }
  });

  return { errors, warnings };
}

/**
 * Enforce quality gates
 */
function enforceQualityGates(gateResults) {
  logHeader('🚫 Quality Gate Enforcement');

  const enforcement = {
    blockRelease: false,
    overallStatus: 'unknown',
    passedGates: [],
    failedGates: [],
    warningGates: [],
    totalScore: 0,
    maxScore: 100,
    qualityGrade: 'F'
  };

  // Calculate overall metrics
  Object.values(gateResults).forEach(gate => {
    enforcement.totalScore += gate.score;

    if (gate.status === 'passed') {
      enforcement.passedGates.push(gate.name);
    } else if (gate.status === 'failed') {
      enforcement.failedGates.push(gate.name);
    } else if (gate.status === 'warning') {
      enforcement.warningGates.push(gate.name);
    }
  });

  // Determine quality grade
  const scorePercentage = (enforcement.totalScore / enforcement.maxScore) * 100;
  if (scorePercentage >= 95) enforcement.qualityGrade = 'A+';
  else if (scorePercentage >= 90) enforcement.qualityGrade = 'A';
  else if (scorePercentage >= 85) enforcement.qualityGrade = 'B+';
  else if (scorePercentage >= 80) enforcement.qualityGrade = 'B';
  else if (scorePercentage >= 75) enforcement.qualityGrade = 'C+';
  else if (scorePercentage >= 70) enforcement.qualityGrade = 'C';
  else if (scorePercentage >= 60) enforcement.qualityGrade = 'D';
  else enforcement.qualityGrade = 'F';

  // Determine enforcement action
  const hasFailedGates = enforcement.failedGates.length > 0;
  const hasRequiredGatesFailed = CONFIG.GATES
    .filter(gate => gate.required)
    .some(gate => gateResults[gate.name]?.status === 'failed');

  if (CONFIG.ENFORCEMENT.WARN_ONLY) {
    enforcement.blockRelease = false;
    enforcement.overallStatus = hasFailedGates ? 'warning' : 'passed';
  } else if (CONFIG.ENFORCEMENT.REQUIRE_ALL_GATES && hasFailedGates) {
    enforcement.blockRelease = true;
    enforcement.overallStatus = 'failed';
  } else if (hasRequiredGatesFailed) {
    enforcement.blockRelease = true;
    enforcement.overallStatus = 'failed';
  } else if (enforcement.warningGates.length > 0 && CONFIG.ENFORCEMENT.STRICT) {
    enforcement.blockRelease = true;
    enforcement.overallStatus = 'failed';
  } else {
    enforcement.blockRelease = false;
    enforcement.overallStatus = enforcement.failedGates.length === 0 ? 'passed' : 'warning';
  }

  // Display enforcement results
  logInfo(`Quality Score: ${enforcement.totalScore}/${enforcement.maxScore} (${scorePercentage.toFixed(1)}%)`);
  logInfo(`Quality Grade: ${enforcement.qualityGrade}`);
  logInfo(`Overall Status: ${enforcement.overallStatus.toUpperCase()}`);

  if (enforcement.blockRelease) {
    logCritical('🚫 RELEASE BLOCKED - Quality gates not met');
    logError('Critical issues must be resolved before release:');
    enforcement.failedGates.forEach(gate => {
      const gateIssues = gateResults[gate].issues;
      gateIssues.forEach(issue => logError(`  • ${issue}`));
    });
  } else if (enforcement.warningGates.length > 0) {
    logWarning('⚠️  Quality warnings detected:');
    enforcement.warningGates.forEach(gate => {
      const gateIssues = gateResults[gate].issues;
      gateIssues.forEach(issue => logWarning(`  • ${issue}`));
    });
  } else {
    logSuccess('✅ All quality gates passed');
  }

  return enforcement;
}

/**
 * Generate quality gate report
 */
function generateQualityReport(gateResults, enforcement) {
  logHeader('📋 Generating Quality Gate Report');

  // Ensure output directory exists
  mkdirSync(CONFIG.OUTPUT_DIR, { recursive: true });

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const reportFile = join(CONFIG.OUTPUT_DIR, `quality-gate-report-${timestamp}.json`);
  const htmlReportFile = join(CONFIG.OUTPUT_DIR, `quality-gate-report-${timestamp}.html`);
  const junitFile = join(CONFIG.OUTPUT_DIR, `quality-gate-junit-${timestamp}.xml`);

  const report = {
    metadata: {
      timestamp: new Date().toISOString(),
      version: '2.0.1',
      enforcement: CONFIG.ENFORCEMENT,
      environment: process.env.NODE_ENV || 'development'
    },
    summary: {
      overallStatus: enforcement.overallStatus,
      qualityGrade: enforcement.qualityGrade,
      totalScore: enforcement.totalScore,
      maxScore: enforcement.maxScore,
      scorePercentage: (enforcement.totalScore / enforcement.maxScore) * 100,
      gatesPassed: enforcement.passedGates.length,
      gatesFailed: enforcement.failedGates.length,
      gatesWarning: enforcement.warningGates.length,
      releaseBlocked: enforcement.blockRelease
    },
    gates: gateResults,
    enforcement,
    recommendations: generateQualityRecommendations(gateResults, enforcement),
    artifacts: {
      reportFile,
      htmlReportFile,
      junitFile
    }
  };

  // Write JSON report
  writeFileSync(reportFile, JSON.stringify(report, null, 2));
  logSuccess(`JSON report generated: ${reportFile}`);

  // Write HTML report
  const htmlReport = generateHTMLQualityReport(report);
  writeFileSync(htmlReportFile, htmlReport);
  logSuccess(`HTML report generated: ${htmlReportFile}`);

  // Write JUnit report for CI integration
  const junitReport = generateJUnitReport(report);
  writeFileSync(junitFile, junitReport);
  logSuccess(`JUnit report generated: ${junitFile}`);

  return report;
}

/**
 * Generate quality recommendations
 */
function generateQualityRecommendations(gateResults, enforcement) {
  const recommendations = [];

  Object.values(gateResults).forEach(gate => {
    if (gate.issues && gate.issues.length > 0) {
      gate.issues.forEach((issue, index) => {
        recommendations.push({
          priority: gate.status === 'failed' ? 'critical' : 'medium',
          category: gate.name,
          gate: gate.name,
          issue,
          action: gate.recommendations?.[index] || 'Address quality gate requirements',
          impact: gate.status === 'failed' ? 'Blocks release' : 'Quality warning'
        });
      });
    }
  });

  // Add overall recommendations
  if (enforcement.blockRelease) {
    recommendations.push({
      priority: 'critical',
      category: 'enforcement',
      gate: 'overall',
      issue: 'Release blocked by quality gates',
      action: 'Resolve all critical quality issues before proceeding with release',
      impact: 'Blocks release'
    });
  }

  if (enforcement.qualityGrade === 'F') {
    recommendations.push({
      priority: 'high',
      category: 'quality',
      gate: 'overall',
      issue: `Poor quality grade: ${enforcement.qualityGrade}`,
      action: 'Improve overall code quality to achieve at least grade B',
      impact: 'Release readiness'
    });
  }

  return recommendations.sort((a, b) => {
    const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return priorityOrder[a.priority] - priorityOrder[b.priority];
  });
}

/**
 * Generate HTML quality report
 */
function generateHTMLQualityReport(report) {
  const { metadata, summary, gates, recommendations } = report;

  const getGateColor = (status) => {
    switch (status) {
      case 'passed': return '#4CAF50';
      case 'warning': return '#ff9800';
      case 'failed': return '#f44336';
      default: return '#9e9e9e';
    }
  };

  const getGateIcon = (status) => {
    switch (status) {
      case 'passed': return '✅';
      case 'warning': return '⚠️';
      case 'failed': return '❌';
      default: return '❓';
    }
  };

  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quality Gate Report - ${metadata.version}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 40px; padding-bottom: 20px; border-bottom: 2px solid #e0e0e0; }
        .status-banner { padding: 20px; border-radius: 8px; text-align: center; font-size: 1.2em; font-weight: bold; margin-bottom: 30px; }
        .status-passed { background: #e8f5e8; color: #2e7d32; border: 2px solid #4caf50; }
        .status-warning { background: #fff3e0; color: #f57c00; border: 2px solid #ff9800; }
        .status-failed { background: #ffebee; color: #c62828; border: 2px solid #f44336; }
        .grade-display { font-size: 3em; font-weight: bold; margin: 20px 0; }
        .gates-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 30px 0; }
        .gate-card { padding: 20px; border-radius: 8px; border-left: 4px solid #ddd; background: #f8f9fa; }
        .score-bar { width: 100%; height: 20px; background: #e0e0e0; border-radius: 10px; overflow: hidden; margin: 10px 0; }
        .score-fill { height: 100%; transition: width 0.3s ease; }
        .recommendations { margin: 30px 0; }
        .recommendation { padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #ff9800; background: #fff3e0; }
        .priority-critical { border-left-color: #f44336; background: #ffebee; }
        .priority-high { border-left-color: #ff9800; background: #fff3e0; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚫 Quality Gate Report</h1>
            <p>Version: ${metadata.version} | Generated: ${new Date(metadata.timestamp).toLocaleString()}</p>
            <div class="status-banner status-${summary.overallStatus}">
                ${summary.overallStatus === 'passed' ? '🎉 QUALITY GATES PASSED' :
                  summary.overallStatus === 'warning' ? '⚠️ QUALITY WARNINGS' :
                  '🚫 QUALITY GATES FAILED - RELEASE BLOCKED'}
            </div>
            <div class="grade-display" style="color: ${getGateColor(summary.overallStatus)}">
                Grade: ${summary.qualityGrade}
            </div>
            <p>Quality Score: ${summary.totalScore}/${summary.maxScore} (${summary.scorePercentage.toFixed(1)}%)</p>
        </div>

        <div class="gates-grid">
            ${Object.entries(gates).map(([gateName, gate]) => `
            <div class="gate-card" style="border-left-color: ${getGateColor(gate.status)};">
                <h3>${getGateIcon(gate.status)} ${gateName.charAt(0).toUpperCase() + gateName.slice(1)} Gate</h3>
                <p><strong>Status:</strong> <span style="color: ${getGateColor(gate.status)}">${gate.status.toUpperCase()}</span></p>
                <p><strong>Score:</strong> ${gate.score}/${gate.maxScore}</p>
                <div class="score-bar">
                    <div class="score-fill" style="width: ${(gate.score / gate.maxScore) * 100}%; background: ${getGateColor(gate.status)};"></div>
                </div>
                ${gate.issues && gate.issues.length > 0 ? `
                <div style="margin-top: 15px;">
                    <strong>Issues:</strong>
                    <ul style="margin: 5px 0; padding-left: 20px;">
                        ${gate.issues.slice(0, 3).map(issue => `<li>${issue}</li>`).join('')}
                        ${gate.issues.length > 3 ? `<li>... and ${gate.issues.length - 3} more</li>` : ''}
                    </ul>
                </div>
                ` : ''}
            </div>
            `).join('')}
        </div>

        <div style="margin: 30px 0; text-align: center;">
            <h3>📊 Summary</h3>
            <div style="display: flex; justify-content: space-around; flex-wrap: wrap;">
                <div style="margin: 10px;">
                    <div style="font-size: 2em; color: #4CAF50;">${summary.gatesPassed}</div>
                    <div>Passed</div>
                </div>
                <div style="margin: 10px;">
                    <div style="font-size: 2em; color: #ff9800;">${summary.gatesWarning}</div>
                    <div>Warnings</div>
                </div>
                <div style="margin: 10px;">
                    <div style="font-size: 2em; color: #f44336;">${summary.gatesFailed}</div>
                    <div>Failed</div>
                </div>
            </div>
        </div>

        ${recommendations.length > 0 ? `
        <div class="recommendations">
            <h3>📋 Quality Recommendations</h3>
            ${recommendations.map(rec => `
            <div class="recommendation priority-${rec.priority}">
                <h4>${rec.category.charAt(0).toUpperCase() + rec.category.slice(1)} - ${rec.priority.toUpperCase()}</h4>
                <p><strong>Issue:</strong> ${rec.issue}</p>
                <p><strong>Action:</strong> ${rec.action}</p>
                <p><strong>Impact:</strong> ${rec.impact}</p>
            </div>
            `).join('')}
        </div>
        ` : ''}

        <div class="footer">
            <p>Generated by Cortex Memory MCP Quality Gate Enforcer</p>
            <p>Enforcement Mode: ${metadata.enforcement.STRICT ? 'Strict' : 'Standard'} |
               ${metadata.enforcement.BLOCK_RELEASES ? 'Blocking' : 'Non-blocking'} Releases</p>
        </div>
    </div>
</body>
</html>`;
}

/**
 * Generate JUnit XML report for CI integration
 */
function generateJUnitReport(report) {
  const { summary, gates, metadata } = report;

  let xml = `<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="Quality Gates" tests="${Object.keys(gates).length}" failures="${summary.gatesFailed}" time="0">
  <testsuite name="Quality Gate Validation" tests="${Object.keys(gates).length}" failures="${summary.gatesFailed}" time="0">
`;

  Object.entries(gates).forEach(([gateName, gate]) => {
    const status = gate.status === 'passed' ? 'passed' : 'failed';
    const failureMessage = gate.issues?.join('; ') || 'Quality gate failed';

    xml += `    <testcase name="${gateName} Gate" classname="QualityGate" time="0">
`;

    if (gate.status !== 'passed') {
      xml += `      <failure message="${failureMessage}">
        Gate: ${gateName}
        Status: ${gate.status}
        Score: ${gate.score}/${gate.maxScore}
        Issues: ${gate.issues?.join(', ') || 'None'}
        Recommendations: ${gate.recommendations?.join(', ') || 'None'}
      </failure>
`;
    }

    xml += `    </testcase>
`;
  });

  xml += `  </testsuite>
</testsuites>`;

  return xml;
}

/**
 * Main quality gate enforcement function
 */
function main() {
  logHeader('🎯 Quality Gate Enforcement');
  logInfo('Enforcing quality standards for release readiness...\n');

  try {
    // Validate all quality gates
    const gateResults = {};

    gateResults.build = validateBuildGate();
    gateResults.coverage = validateCoverageGate();
    gateResults.performance = validatePerformanceGate();
    gateResults.security = validateSecurityGate();

    // Enforce quality gates
    const enforcement = enforceQualityGates(gateResults);

    // Generate report
    const report = generateQualityReport(gateResults, enforcement);

    // Final summary and action
    logHeader('📊 Quality Gate Enforcement Summary');

    logInfo(`Quality Grade: ${enforcement.qualityGrade}`);
    logInfo(`Score: ${enforcement.totalScore}/${enforcement.maxScore} (${((enforcement.totalScore / enforcement.maxScore) * 100).toFixed(1)}%)`);
    logInfo(`Status: ${enforcement.overallStatus.toUpperCase()}`);

    if (enforcement.blockRelease) {
      logCritical('\n🚫 RELEASE BLOCKED BY QUALITY GATES');
      logError('Critical quality issues must be resolved before release:');

      Object.values(gateResults)
        .filter(gate => gate.status === 'failed')
        .forEach(gate => {
          logError(`\n${gate.name.toUpperCase()} Gate:`);
          gate.issues.forEach(issue => logError(`  • ${issue}`));
          logError(`  Recommendations:`);
          gate.recommendations.forEach(rec => logError(`    - ${rec}`));
        });

      logError(`\n📄 Quality Report: ${report.artifacts.reportFile}`);
      logError(`🌐 HTML Report: ${report.artifacts.htmlReportFile}`);

      if (CONFIG.ENFORCEMENT.BLOCK_RELEASES) {
        logError('\n💡 To proceed with release:');
        logError('  1. Fix all critical quality issues');
        logError('  2. Re-run quality gate validation');
        logError('  3. Ensure all gates pass');
        logError('\n⚠️  To override (not recommended):');
        logError('  Set Quality_Gate_Block_Release=false environment variable');
      }

      process.exit(1);
    } else if (enforcement.warningGates.length > 0) {
      logWarning('\n⚠️  QUALITY WARNINGS DETECTED');
      logInfo('Non-critical issues found. Review before release:');

      enforcement.warningGates.forEach(gateName => {
        const gate = gateResults[gateName];
        logWarning(`\n${gateName.toUpperCase()} Gate:`);
        gate.issues.forEach(issue => logWarning(`  • ${issue}`));
      });

      logSuccess('\n✅ QUALITY GATES PASSED - Release allowed with warnings');
    } else {
      logSuccess('\n🎉 ALL QUALITY GATES PASSED - Ready for release');
    }

    logSuccess('\n✅ Quality gate enforcement completed');
    logInfo(`📄 Reports generated in: ${CONFIG.OUTPUT_DIR}`);

  } catch (error) {
    logError(`Quality gate enforcement failed: ${error.message}`);
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { validateBuildGate, validateCoverageGate, validatePerformanceGate, validateSecurityGate };