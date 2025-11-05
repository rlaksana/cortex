#!/usr/bin/env node

/**
 * Release Gate Report Generator
 *
 * Generates comprehensive release gate reports with detailed metrics,
 * artifact collection, and attachment support for releases.
 */

import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

// Configuration
const CONFIG = {
  OUTPUT_DIR: join(projectRoot, 'artifacts', 'release-gates'),
  ARTIFACTS_DIR: join(projectRoot, 'artifacts'),
  COVERAGE_DIR: join(projectRoot, 'coverage'),
  TEST_RESULTS_DIR: join(projectRoot, 'test-results'),
  BENCHMARK_DIR: join(projectRoot, 'artifacts', 'bench'),
  SECURITY_REPORTS_DIR: join(projectRoot, 'security-reports'),
  // Report retention
  RETENTION_DAYS: 90,
  // Release metadata
  RELEASE_METADATA: {
    version: process.env.npm_package_version || '2.0.1',
    branch: getCurrentGitBranch(),
    commit: getCurrentGitCommit(),
    buildNumber: process.env.BUILD_NUMBER || 'local'
  }
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

function logSuccess(message) {
  log(`✅ ${message}`, COLORS.green);
}

function logInfo(message) {
  log(`ℹ️  ${message}`, COLORS.blue);
}

function logHeader(message) {
  log(`\n${COLORS.bold}${message}${COLORS.reset}`);
  log('='.repeat(message.length), COLORS.cyan);
}

/**
 * Get current git branch
 */
function getCurrentGitBranch() {
  try {
    return execSync('git rev-parse --abbrev-ref HEAD', { encoding: 'utf8' }).trim();
  } catch (error) {
    return 'unknown';
  }
}

/**
 * Get current git commit hash
 */
function getCurrentGitCommit() {
  try {
    return execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim();
  } catch (error) {
    return 'unknown';
  }
}

/**
 * Collect build artifacts
 */
function collectBuildArtifacts() {
  logInfo('Collecting build artifacts...');

  const artifacts = {
    build: {
      status: 'unknown',
      artifacts: [],
      size: 0
    },
    dist: {
      status: 'unknown',
      files: [],
      size: 0
    }
  };

  // Check if build exists
  const distDir = join(projectRoot, 'dist');
  if (existsSync(distDir)) {
    try {
      const files = execSync(`find "${distDir}" -type f -name "*.js" -o -name "*.mjs" -o -name "*.json" | head -20`, { encoding: 'utf8' });
      artifacts.dist.files = files.trim().split('\n').filter(f => f.length > 0);
      artifacts.dist.status = 'exists';
      artifacts.dist.size = getDirectorySize(distDir);
      logSuccess(`Found ${artifacts.dist.files.length} distribution files`);
    } catch (error) {
      artifacts.dist.status = 'error';
      artifacts.dist.error = error.message;
    }
  } else {
    artifacts.dist.status = 'missing';
    logInfo('No distribution files found');
  }

  // Check for build artifacts
  const artifactsDir = join(CONFIG.ARTIFACTS_DIR);
  if (existsSync(artifactsDir)) {
    try {
      const artifactFiles = execSync(`find "${artifactsDir}" -type f | head -50`, { encoding: 'utf8' });
      artifacts.build.artifacts = artifactFiles.trim().split('\n').filter(f => f.length > 0);
      artifacts.build.status = 'exists';
      artifacts.build.size = getDirectorySize(artifactsDir);
      logSuccess(`Found ${artifacts.build.artifacts.length} build artifacts`);
    } catch (error) {
      artifacts.build.status = 'error';
      artifacts.build.error = error.message;
    }
  }

  return artifacts;
}

/**
 * Collect test results and coverage
 */
function collectTestResults() {
  logInfo('Collecting test results and coverage...');

  const testResults = {
    unit: {
      status: 'unknown',
      results: {},
      summary: {}
    },
    integration: {
      status: 'unknown',
      results: {},
      summary: {}
    },
    coverage: {
      status: 'unknown',
      metrics: {},
      summary: {}
    }
  };

  // Unit test results
  const unitTestFile = join(CONFIG.TEST_RESULTS_DIR, 'unit-test-results.json');
  if (existsSync(unitTestFile)) {
    try {
      testResults.unit.results = JSON.parse(readFileSync(unitTestFile, 'utf8'));
      testResults.unit.status = 'exists';
      logSuccess('Unit test results found');
    } catch (error) {
      testResults.unit.status = 'error';
      testResults.unit.error = error.message;
    }
  }

  // Integration test results
  const integrationTestFile = join(CONFIG.TEST_RESULTS_DIR, 'integration-test-results.json');
  if (existsSync(integrationTestFile)) {
    try {
      testResults.integration.results = JSON.parse(readFileSync(integrationTestFile, 'utf8'));
      testResults.integration.status = 'exists';
      logSuccess('Integration test results found');
    } catch (error) {
      testResults.integration.status = 'error';
      testResults.integration.error = error.message;
    }
  }

  // Coverage results
  const coverageFile = join(CONFIG.COVERAGE_DIR, 'coverage-summary.json');
  if (existsSync(coverageFile)) {
    try {
      const coverageData = JSON.parse(readFileSync(coverageFile, 'utf8'));
      testResults.coverage.metrics = coverageData.total;
      testResults.coverage.status = 'exists';
      testResults.coverage.summary = {
        statements: coverageData.total.statements.pct,
        branches: coverageData.total.branches.pct,
        functions: coverageData.total.functions.pct,
        lines: coverageData.total.lines.pct
      };
      logSuccess('Coverage report found');
    } catch (error) {
      testResults.coverage.status = 'error';
      testResults.coverage.error = error.message;
    }
  }

  return testResults;
}

/**
 * Collect performance benchmarks
 */
function collectPerformanceResults() {
  logInfo('Collecting performance benchmark results...');

  const performance = {
    benchmarks: {
      status: 'unknown',
      results: {},
      summary: {}
    },
    loadTests: {
      status: 'unknown',
      results: {},
      summary: {}
    }
  };

  // Benchmark results
  const benchmarkFile = join(CONFIG.BENCHMARK_DIR, 'benchmark-results.json');
  if (existsSync(benchmarkFile)) {
    try {
      const benchmarkData = JSON.parse(readFileSync(benchmarkFile, 'utf8'));
      performance.benchmarks.results = benchmarkData;
      performance.benchmarks.status = 'exists';

      // Generate summary
      if (benchmarkData.results && Array.isArray(benchmarkData.results)) {
        const summary = {
          scenarios: benchmarkData.results.length,
          avgP95: benchmarkData.results.reduce((sum, r) => sum + (r.metrics?.latencies?.p95 || 0), 0) / benchmarkData.results.length,
          avgThroughput: benchmarkData.results.reduce((sum, r) => sum + (r.metrics?.throughput || 0), 0) / benchmarkData.results.length,
          avgErrorRate: benchmarkData.results.reduce((sum, r) => sum + (r.metrics?.errorRate || 0), 0) / benchmarkData.results.length
        };
        performance.benchmarks.summary = summary;
      }

      logSuccess('Benchmark results found');
    } catch (error) {
      performance.benchmarks.status = 'error';
      performance.benchmarks.error = error.message;
    }
  }

  // Load test results
  const loadTestFile = join(CONFIG.BENCHMARK_DIR, 'load-test-results.json');
  if (existsSync(loadTestFile)) {
    try {
      const loadTestData = JSON.parse(readFileSync(loadTestFile, 'utf8'));
      performance.loadTests.results = loadTestData;
      performance.loadTests.status = 'exists';
      logSuccess('Load test results found');
    } catch (error) {
      performance.loadTests.status = 'error';
      performance.loadTests.error = error.message;
    }
  }

  return performance;
}

/**
 * Collect security scan results
 */
function collectSecurityResults() {
  logInfo('Collecting security scan results...');

  const security = {
    audit: {
      status: 'unknown',
      results: {},
      summary: {}
    },
    eslint: {
      status: 'unknown',
      results: {},
      summary: {}
    },
    tests: {
      status: 'unknown',
      results: {},
      summary: {}
    }
  };

  // Security audit results
  const auditFile = join(CONFIG.SECURITY_REPORTS_DIR, 'audit-report.json');
  if (existsSync(auditFile)) {
    try {
      const auditData = JSON.parse(readFileSync(auditFile, 'utf8'));
      security.audit.results = auditData;
      security.audit.status = 'exists';
      security.audit.summary = {
        totalVulnerabilities: Object.keys(auditData.vulnerabilities || {}).length,
        critical: Object.values(auditData.vulnerabilities || {}).filter(v => v.severity === 'critical').length,
        high: Object.values(auditData.vulnerabilities || {}).filter(v => v.severity === 'high').length,
        moderate: Object.values(auditData.vulnerabilities || {}).filter(v => v.severity === 'moderate').length,
        low: Object.values(auditData.vulnerabilities || {}).filter(v => v.severity === 'low').length
      };
      logSuccess('Security audit results found');
    } catch (error) {
      security.audit.status = 'error';
      security.audit.error = error.message;
    }
  }

  // ESLint security results
  const eslintFile = join(CONFIG.SECURITY_REPORTS_DIR, 'eslint-security-report.json');
  if (existsSync(eslintFile)) {
    try {
      const eslintData = JSON.parse(readFileSync(eslintFile, 'utf8'));
      security.eslint.results = eslintData;
      security.eslint.status = 'exists';
      security.eslint.summary = {
        totalIssues: eslintData.length || 0,
        errors: eslintData.filter(r => r.severity === 'error').length,
        warnings: eslintData.filter(r => r.severity === 'warning').length
      };
      logSuccess('ESLint security results found');
    } catch (error) {
      security.eslint.status = 'error';
      security.eslint.error = error.message;
    }
  }

  // Security test results
  const securityTestFile = join(CONFIG.TEST_RESULTS_DIR, 'security-test-results.json');
  if (existsSync(securityTestFile)) {
    try {
      const securityTestData = JSON.parse(readFileSync(securityTestFile, 'utf8'));
      security.tests.results = securityTestData;
      security.tests.status = 'exists';
      security.tests.summary = {
        totalTests: securityTestData.numTotalTests || 0,
        passed: securityTestData.numPassedTests || 0,
        failed: securityTestData.numFailedTests || 0,
        skipped: securityTestData.numPendingTests || 0
      };
      logSuccess('Security test results found');
    } catch (error) {
      security.tests.status = 'error';
      security.tests.error = error.message;
    }
  }

  return security;
}

/**
 * Get directory size
 */
function getDirectorySize(dirPath) {
  try {
    const result = execSync(`du -sb "${dirPath}" 2>/dev/null || echo "0"`, { encoding: 'utf8' });
    return parseInt(result.trim().split('\t')[0]) || 0;
  } catch (error) {
    return 0;
  }
}

/**
 * Generate CSV metrics export
 */
function generateCSVReport(report) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const csvFile = join(CONFIG.OUTPUT_DIR, `release-metrics-${timestamp}.csv`);

  let csv = 'Category,Metric,Value,Unit,Status\n';

  // Build metrics
  csv += `Build,Distribution Files,${report.build.dist.files.length},files,${report.build.dist.status}\n`;
  csv += `Build,Distribution Size,${report.build.dist.size},bytes,${report.build.dist.status}\n`;
  csv += `Build,Build Artifacts,${report.build.build.artifacts.length},files,${report.build.build.status}\n`;

  // Test metrics
  if (report.testResults.coverage.summary) {
    csv += `Coverage,Statements,${report.testResults.coverage.summary.statements},percent,${report.testResults.coverage.status}\n`;
    csv += `Coverage,Branches,${report.testResults.coverage.summary.branches},percent,${report.testResults.coverage.status}\n`;
    csv += `Coverage,Functions,${report.testResults.coverage.summary.functions},percent,${report.testResults.coverage.status}\n`;
    csv += `Coverage,Lines,${report.testResults.coverage.summary.lines},percent,${report.testResults.coverage.status}\n`;
  }

  // Performance metrics
  if (report.performance.benchmarks.summary) {
    const summary = report.performance.benchmarks.summary;
    csv += `Performance,Scenarios Tested,${summary.scenarios},count,${report.performance.benchmarks.status}\n`;
    csv += `Performance,Average P95 Latency,${summary.avgP95.toFixed(2)},ms,${report.performance.benchmarks.status}\n`;
    csv += `Performance,Average Throughput,${summary.avgThroughput.toFixed(2)},ops/s,${report.performance.benchmarks.status}\n`;
    csv += `Performance,Average Error Rate,${summary.avgErrorRate.toFixed(2)},%,${report.performance.benchmarks.status}\n`;
  }

  // Security metrics
  if (report.security.audit.summary) {
    const summary = report.security.audit.summary;
    csv += `Security,Total Vulnerabilities,${summary.totalVulnerabilities},count,${report.security.audit.status}\n`;
    csv += `Security,Critical,${summary.critical},count,${report.security.audit.status}\n`;
    csv += `Security,High,${summary.high},count,${report.security.audit.status}\n`;
    csv += `Security,Moderate,${summary.moderate},count,${report.security.audit.status}\n`;
    csv += `Security,Low,${summary.low},count,${report.security.audit.status}\n`;
  }

  writeFileSync(csvFile, csv);
  logSuccess(`CSV metrics report generated: ${csvFile}`);
  return csvFile;
}

/**
 * Generate comprehensive release gate report
 */
function generateReleaseReport() {
  logHeader('📋 Generating Release Gate Report');

  // Ensure output directory exists
  mkdirSync(CONFIG.OUTPUT_DIR, { recursive: true });

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const reportFile = join(CONFIG.OUTPUT_DIR, `release-gate-report-${timestamp}.json`);
  const htmlReportFile = join(CONFIG.OUTPUT_DIR, `release-gate-report-${timestamp}.html`);

  // Collect all artifacts and results
  const build = collectBuildArtifacts();
  const testResults = collectTestResults();
  const performance = collectPerformanceResults();
  const security = collectSecurityResults();

  const report = {
    metadata: {
      timestamp: new Date().toISOString(),
      version: CONFIG.RELEASE_METADATA.version,
      branch: CONFIG.RELEASE_METADATA.branch,
      commit: CONFIG.RELEASE_METADATA.commit,
      buildNumber: CONFIG.RELEASE_METADATA.buildNumber,
      environment: process.env.NODE_ENV || 'development',
      nodeVersion: process.version,
      platform: process.platform,
      generatedBy: 'Release Gate Reporter v2.0.1'
    },
    summary: {
      buildStatus: build.dist.status === 'exists' && build.build.status === 'exists' ? 'success' : 'failed',
      testStatus: testResults.coverage.status === 'exists' ? 'success' : 'failed',
      performanceStatus: performance.benchmarks.status === 'exists' ? 'success' : 'failed',
      securityStatus: security.audit.status === 'exists' ? 'success' : 'failed',
      overallStatus: 'unknown', // Will be calculated
      artifactCount: build.dist.files.length + build.build.artifacts.length,
      totalSize: build.dist.size + build.build.size
    },
    artifacts: {
      build,
      testResults,
      performance,
      security
    },
    compliance: {
      coverageThresholds: {
        statements: testResults.coverage.summary?.statements || 0,
        branches: testResults.coverage.summary?.branches || 0,
        functions: testResults.coverage.summary?.functions || 0,
        lines: testResults.coverage.summary?.lines || 0,
        required: 90
      },
      performanceThresholds: {
        p95Latency: performance.benchmarks.summary?.avgP95 || 0,
        throughput: performance.benchmarks.summary?.avgThroughput || 0,
        errorRate: performance.benchmarks.summary?.avgErrorRate || 0,
        requiredP95: 1000,
        requiredThroughput: 100,
        requiredErrorRate: 1.0
      },
      securityCompliance: {
        criticalVulnerabilities: security.audit.summary?.critical || 0,
        highVulnerabilities: security.audit.summary?.high || 0,
        requiredMaximum: 0
      }
    },
    readiness: {
      buildReady: build.dist.status === 'exists' && build.build.status === 'exists',
      coverageReady: (testResults.coverage.summary?.statements || 0) >= 90,
      performanceReady: (performance.benchmarks.summary?.avgP95 || 0) <= 1000,
      securityReady: (security.audit.summary?.critical || 0) === 0 && (security.audit.summary?.high || 0) === 0,
      readyForRelease: false // Will be calculated
    },
    recommendations: generateReleaseRecommendations({
      build,
      testResults,
      performance,
      security
    }),
    artifacts: {
      reportFile,
      htmlReportFile,
      csvFile: null, // Will be set after generation
      allFiles: {
        build: build.dist.files.concat(build.build.artifacts),
        testResults: [
          join(CONFIG.TEST_RESULTS_DIR, 'unit-test-results.json'),
          join(CONFIG.TEST_RESULTS_DIR, 'integration-test-results.json'),
          join(CONFIG.COVERAGE_DIR, 'coverage-summary.json')
        ],
        performance: [
          join(CONFIG.BENCHMARK_DIR, 'benchmark-results.json'),
          join(CONFIG.BENCHMARK_DIR, 'load-test-results.json')
        ],
        security: [
          join(CONFIG.SECURITY_REPORTS_DIR, 'audit-report.json'),
          join(CONFIG.SECURITY_REPORTS_DIR, 'eslint-security-report.json')
        ]
      }
    }
  };

  // Calculate overall status
  const readyGates = [
    report.readiness.buildReady,
    report.readiness.coverageReady,
    report.readiness.performanceReady,
    report.readiness.securityReady
  ];

  report.readiness.readyForRelease = readyGates.every(Boolean);
  report.summary.overallStatus = report.readiness.readyForRelease ? 'success' : 'failed';

  // Write JSON report
  writeFileSync(reportFile, JSON.stringify(report, null, 2));
  logSuccess(`JSON report generated: ${reportFile}`);

  // Write HTML report
  const htmlReport = generateHTMLReleaseReport(report);
  writeFileSync(htmlReportFile, htmlReport);
  logSuccess(`HTML report generated: ${htmlReportFile}`);

  // Generate CSV report
  const csvFile = generateCSVReport(report);
  report.artifacts.csvFile = csvFile;

  // Generate attachment manifest for releases
  const attachmentManifest = generateAttachmentManifest(report);
  const manifestFile = join(CONFIG.OUTPUT_DIR, `attachment-manifest-${timestamp}.json`);
  writeFileSync(manifestFile, attachmentManifest);
  logSuccess(`Attachment manifest generated: ${manifestFile}`);

  return report;
}

/**
 * Generate release recommendations
 */
function generateReleaseRecommendations(results) {
  const recommendations = [];

  // Build recommendations
  if (results.build.dist.status !== 'exists') {
    recommendations.push({
      priority: 'critical',
      category: 'Build',
      issue: 'Distribution files missing',
      action: 'Run `npm run build` to generate distribution files'
    });
  }

  // Coverage recommendations
  const coverage = results.testResults.coverage.summary;
  if (!coverage || coverage.statements < 90) {
    recommendations.push({
      priority: 'high',
      category: 'Testing',
      issue: `Test coverage below 90%: ${coverage?.statements || 0}%`,
      action: 'Add more unit tests and integration tests to meet 90% coverage requirement'
    });
  }

  // Performance recommendations
  const perf = results.performance.benchmarks.summary;
  if (!perf || perf.avgP95 > 1000) {
    recommendations.push({
      priority: 'high',
      category: 'Performance',
      issue: `P95 latency above 1s threshold: ${perf?.avgP95?.toFixed(2) || 'N/A'}ms`,
      action: 'Optimize performance bottlenecks to meet P95 < 1s requirement'
    });
  }

  // Security recommendations
  const sec = results.security.audit.summary;
  if (sec && (sec.critical > 0 || sec.high > 0)) {
    recommendations.push({
      priority: 'critical',
      category: 'Security',
      issue: `Security vulnerabilities detected: ${sec.critical} critical, ${sec.high} high`,
      action: 'Address all high and critical security vulnerabilities before release'
    });
  }

  return recommendations.sort((a, b) => {
    const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return priorityOrder[a.priority] - priorityOrder[b.priority];
  });
}

/**
 * Generate HTML release report
 */
function generateHTMLReleaseReport(report) {
  const { metadata, summary, readiness, compliance, recommendations } = report;

  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Release Gate Report - ${metadata.version}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 40px; padding-bottom: 20px; border-bottom: 2px solid #e0e0e0; }
        .status-banner { padding: 20px; border-radius: 8px; text-align: center; font-size: 1.2em; font-weight: bold; margin-bottom: 30px; }
        .status-success { background: #e8f5e8; color: #2e7d32; border: 2px solid #4caf50; }
        .status-failed { background: #ffebee; color: #c62828; border: 2px solid #f44336; }
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .metric-card { padding: 15px; border-radius: 8px; background: #f5f5f5; text-align: center; }
        .metric-value { font-size: 1.5em; font-weight: bold; margin-bottom: 5px; }
        .readiness-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }
        .readiness-item { padding: 20px; border-radius: 8px; text-align: center; }
        .readiness-pass { background: #e8f5e8; color: #2e7d32; border: 2px solid #4caf50; }
        .readiness-fail { background: #ffebee; color: #c62828; border: 2px solid #f44336; }
        .compliance-section { margin: 30px 0; }
        .compliance-bar { width: 100%; height: 20px; background: #e0e0e0; border-radius: 10px; overflow: hidden; margin: 10px 0; }
        .compliance-fill { height: 100%; transition: width 0.3s ease; }
        .compliance-good { background: #4caf50; }
        .compliance-warning { background: #ff9800; }
        .compliance-bad { background: #f44336; }
        .recommendations { margin: 30px 0; }
        .recommendation { padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #ff9800; background: #fff3e0; }
        .priority-critical { border-left-color: #f44336; background: #ffebee; }
        .priority-high { border-left-color: #ff9800; background: #fff3e0; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #666; }
        .metadata { font-size: 0.9em; color: #666; text-align: center; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Release Gate Report</h1>
            <div class="metadata">
                Version: ${metadata.version} | Branch: ${metadata.branch} | Commit: ${metadata.commit.substring(0, 8)}
                <br>Generated: ${new Date(metadata.timestamp).toLocaleString()} | Build: ${metadata.buildNumber}
            </div>
            <div class="status-banner ${summary.overallStatus === 'success' ? 'status-success' : 'status-failed'}">
                ${summary.overallStatus === 'success' ? '🎉 READY FOR RELEASE' : '🚫 NOT READY FOR RELEASE'}
            </div>
        </div>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value">${summary.artifactCount}</div>
                <div>Artifacts</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">${(summary.totalSize / 1024 / 1024).toFixed(1)}MB</div>
                <div>Total Size</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: ${readiness.buildReady ? '#4CAF50' : '#f44336'}">
                    ${readiness.buildReady ? '✅' : '❌'}
                </div>
                <div>Build Ready</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: ${readiness.coverageReady ? '#4CAF50' : '#f44336'}">
                    ${readiness.coverageReady ? '✅' : '❌'}
                </div>
                <div>Coverage Ready</div>
            </div>
        </div>

        <div class="readiness-grid">
            <div class="readiness-item ${readiness.buildReady ? 'readiness-pass' : 'readiness-fail'}">
                <h3>🏗️ Build</h3>
                <div style="font-size: 2em;">${readiness.buildReady ? '✅' : '❌'}</div>
                <p>${readiness.buildReady ? 'Build artifacts ready' : 'Build issues detected'}</p>
            </div>
            <div class="readiness-item ${readiness.coverageReady ? 'readiness-pass' : 'readiness-fail'}">
                <h3>📊 Coverage</h3>
                <div style="font-size: 2em;">${readiness.coverageReady ? '✅' : '❌'}</div>
                <p>${readiness.coverageReady ? '≥90% coverage met' : 'Coverage below threshold'}</p>
            </div>
            <div class="readiness-item ${readiness.performanceReady ? 'readiness-pass' : 'readiness-fail'}">
                <h3>⚡ Performance</h3>
                <div style="font-size: 2em;">${readiness.performanceReady ? '✅' : '❌'}</div>
                <p>${readiness.performanceReady ? 'P95 < 1s achieved' : 'Performance below targets'}</p>
            </div>
            <div class="readiness-item ${readiness.securityReady ? 'readiness-pass' : 'readiness-fail'}">
                <h3>🔒 Security</h3>
                <div style="font-size: 2em;">${readiness.securityReady ? '✅' : '❌'}</div>
                <p>${readiness.securityReady ? 'No critical issues' : 'Security issues detected'}</p>
            </div>
        </div>

        <div class="compliance-section">
            <h3>📈 Compliance Metrics</h3>

            <div style="margin: 20px 0;">
                <h4>Test Coverage</h4>
                <div class="compliance-bar">
                    <div class="compliance-fill ${compliance.coverageThresholds.statements >= 90 ? 'compliance-good' : 'compliance-bad'}"
                         style="width: ${Math.min(compliance.coverageThresholds.statements, 100)}%"></div>
                </div>
                <p>Statements: ${compliance.coverageThresholds.statements}% (Required: ≥90%)</p>

                <div class="compliance-bar">
                    <div class="compliance-fill ${compliance.coverageThresholds.branches >= 90 ? 'compliance-good' : 'compliance-bad'}"
                         style="width: ${Math.min(compliance.coverageThresholds.branches, 100)}%"></div>
                </div>
                <p>Branches: ${compliance.coverageThresholds.branches}% (Required: ≥90%)</p>
            </div>

            <div style="margin: 20px 0;">
                <h4>Performance</h4>
                <p>P95 Latency: ${compliance.performanceThresholds.p95Latency.toFixed(2)}ms (Required: <1000ms)</p>
                <p>Throughput: ${compliance.performanceThresholds.throughput.toFixed(2)} ops/s (Required: ≥100 ops/s)</p>
                <p>Error Rate: ${compliance.performanceThresholds.errorRate.toFixed(2)}% (Required: <1.0%)</p>
            </div>

            <div style="margin: 20px 0;">
                <h4>Security</h4>
                <p>Critical Vulnerabilities: ${compliance.securityCompliance.criticalVulnerabilities} (Required: 0)</p>
                <p>High Vulnerabilities: ${compliance.securityCompliance.highVulnerabilities} (Required: 0)</p>
            </div>
        </div>

        ${recommendations.length > 0 ? `
        <div class="recommendations">
            <h3>📋 Release Recommendations</h3>
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
            <p>Generated by Cortex Memory MCP Release Gate Reporter</p>
            <p>Environment: ${metadata.environment} | Node.js: ${metadata.nodeVersion}</p>
        </div>
    </div>
</body>
</html>`;
}

/**
 * Generate attachment manifest for releases
 */
function generateAttachmentManifest(report) {
  const manifest = {
    version: report.metadata.version,
    timestamp: report.metadata.timestamp,
    attachments: [
      {
        name: 'release-gate-report.json',
        type: 'application/json',
        description: 'Comprehensive release gate report with all metrics and results',
        required: true
      },
      {
        name: 'release-gate-report.html',
        type: 'text/html',
        description: 'HTML visualization of release gate report',
        required: false
      },
      {
        name: 'release-metrics.csv',
        type: 'text/csv',
        description: 'CSV export of all release metrics',
        required: false
      },
      {
        name: 'attachment-manifest.json',
        type: 'application/json',
        description: 'Manifest of all release artifacts',
        required: true
      }
    ],
    artifacts: {
      build: report.artifacts.build,
      testResults: report.artifacts.testResults,
      performance: report.artifacts.performance,
      security: report.artifacts.security
    },
    readyForRelease: report.readiness.readyForRelease,
    compliance: report.compliance,
    summary: {
      totalChecks: 4,
      passedChecks: Object.values(report.readiness).filter(Boolean).length,
      failedChecks: Object.values(report.readiness).filter(v => !v).length
    }
  };

  return manifest;
}

/**
 * Main function
 */
function main() {
  try {
    const report = generateReleaseReport();

    logHeader('📊 Release Gate Report Summary');
    logInfo(`Version: ${report.metadata.version}`);
    logInfo(`Branch: ${report.metadata.branch}`);
    logInfo(`Commit: ${report.metadata.commit.substring(0, 8)}`);

    logInfo('\nReadiness Status:');
    Object.entries(report.readiness).forEach(([gate, ready]) => {
      const status = ready ? '✅' : '❌';
      const gateName = gate.replace(/([A-Z])/g, ' $1').trim();
      const gateDisplay = gateName.charAt(0).toUpperCase() + gateName.slice(1);
      log(`  ${status} ${gateDisplay}`, ready ? COLORS.green : COLORS.red);
    });

    if (report.readiness.readyForRelease) {
      logSuccess('\n🎉 RELEASE READY - All gates passed');
      logSuccess('Attachments generated and ready for release deployment');
    } else {
      logInfo('\n🚫 RELEASE NOT READY - Some gates failed');
      logInfo('Address recommendations before proceeding with release');
    }

    logInfo(`\n📄 Report files:`);
    logInfo(`  JSON: ${report.artifacts.reportFile}`);
    logInfo(`  HTML: ${report.artifacts.htmlReportFile}`);
    logInfo(`  CSV: ${report.artifacts.csvFile}`);
    logInfo(`  Manifest: ${join(CONFIG.OUTPUT_DIR, `attachment-manifest-${new Date().toISOString().replace(/[:.]/g, '-')}.json`)}`);

  } catch (error) {
    logError(`Release gate report generation failed: ${error.message}`);
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { generateReleaseReport };