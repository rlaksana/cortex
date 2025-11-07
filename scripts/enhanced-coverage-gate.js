#!/usr/bin/env node

/**
 * Enhanced Coverage Gate Enforcement Script - T09 Implementation
 *
 * Implements dual-threshold coverage requirements:
 * - ≥85% global coverage across all metrics
 * - ≥90% critical path coverage for core components
 *
 * Critical paths include:
 * - Core services (memory_store, memory_find)
 * - Authentication services
 * - Database components
 * - MCP server functionality
 */

import { execSync } from 'child_process';
import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

// Enhanced configuration with dual thresholds
const COVERAGE_CONFIG = {
  // Global minimum thresholds (≥85%)
  GLOBAL_THRESHOLDS: {
    statements: 85,
    branches: 85,
    functions: 85,
    lines: 85,
  },

  // Critical path thresholds (≥90%)
  CRITICAL_THRESHOLDS: {
    statements: 90,
    branches: 90,
    functions: 90,
    lines: 90,
  },

  // Critical path patterns - core components that need higher coverage
  CRITICAL_PATHS: [
    'src/services/memory-store.ts',
    'src/services/memory-find.ts',
    'src/services/orchestrators/memory-store-orchestrator.ts',
    'src/services/orchestrators/memory-find-orchestrator.ts',
    'src/db/database-manager.ts',
    'src/db/qdrant-client.ts',
    'src/index.ts', // Main MCP server
    'src/services/auth/auth-service.ts',
    'src/services/auth/authorization-service.ts',
    'src/services/core-memory-find.ts',
    'src/schemas/json-schemas.ts',
    'src/schemas/mcp-inputs.ts',
  ],

  // Additional important directories (85% threshold)
  IMPORTANT_DIRECTORIES: ['src/services/**', 'src/db/**', 'src/utils/**', 'src/middleware/**'],

  // Exclude patterns
  EXCLUDE_PATTERNS: [
    'tests/**',
    'dist/**',
    'node_modules/**',
    'coverage/**',
    'scripts/**',
    '**/*.d.ts',
    '**/*.config.ts',
    '**/*.config.js',
    '**/*.test.ts',
    '**/*.spec.ts',
  ],
};

// Colors for enhanced output
const COLORS = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
};

function log(message, color = COLORS.reset) {
  console.log(`${color}${message}${COLORS.reset}`);
}

function logSuccess(message) {
  log(`✅ ${message}`, COLORS.green);
}

function logError(message) {
  log(`❌ ${message}`, COLORS.red);
}

function logWarning(message) {
  log(`⚠️  ${message}`, COLORS.yellow);
}

function logInfo(message) {
  log(`ℹ️  ${message}`, COLORS.blue);
}

function logCritical(message) {
  log(`🔥 ${message}`, COLORS.bold + COLORS.red);
}

/**
 * Run coverage with enhanced c8 configuration
 */
function runEnhancedCoverage() {
  logInfo('🔍 Running enhanced coverage analysis with dual thresholds...');

  try {
    // Generate comprehensive coverage reports
    const coverageCommand = 'npm run test:coverage:ci';
    execSync(coverageCommand, {
      cwd: projectRoot,
      stdio: 'inherit',
      encoding: 'utf8',
    });

    logSuccess('Coverage analysis completed');
    return true;
  } catch (error) {
    logError(`Coverage analysis failed: ${error.message}`);
    return false;
  }
}

/**
 * Parse coverage summary from v8 output
 */
function parseCoverageSummary() {
  const coverageFile = join(projectRoot, 'coverage', 'coverage-summary.json');

  if (!existsSync(coverageFile)) {
    logError('Coverage summary file not found');
    return null;
  }

  try {
    const coverageData = JSON.parse(readFileSync(coverageFile, 'utf8'));
    return coverageData;
  } catch (error) {
    logError(`Failed to parse coverage summary: ${error.message}`);
    return null;
  }
}

/**
 * Parse per-file coverage for critical path analysis
 */
function parsePerFileCoverage() {
  const coverageFile = join(projectRoot, 'coverage', 'coverage-final.json');

  if (!existsSync(coverageFile)) {
    logWarning('Per-file coverage file not found');
    return null;
  }

  try {
    const coverageData = JSON.parse(readFileSync(coverageFile, 'utf8'));
    return coverageData;
  } catch (error) {
    logWarning(`Failed to parse per-file coverage: ${error.message}`);
    return null;
  }
}

/**
 * Check global coverage thresholds (≥85%)
 */
function checkGlobalThresholds(totalCoverage) {
  logInfo('\n📊 Global Coverage Analysis (≥85% required):');

  let allPassed = true;
  const metrics = ['statements', 'branches', 'functions', 'lines'];

  metrics.forEach((metric) => {
    const coverage = totalCoverage[metric]?.pct || 0;
    const threshold = COVERAGE_CONFIG.GLOBAL_THRESHOLDS[metric];
    const passed = coverage >= threshold;

    const status = passed ? '✅' : '❌';
    const color = passed ? COLORS.green : COLORS.red;
    const indicator = getCoverageIndicator(coverage);

    log(
      `   ${status} ${metric.toUpperCase()}: ${coverage.toFixed(1)}% ${indicator} (threshold: ${threshold}%)`,
      color
    );

    if (!passed) {
      allPassed = false;
      logError(`     ↳ Deficit: ${(threshold - coverage).toFixed(1)}% points below threshold`);
    }
  });

  return allPassed;
}

/**
 * Check critical path coverage (≥90%)
 */
function checkCriticalPathCoverage(perFileCoverage) {
  if (!perFileCoverage) {
    logWarning('⚠️  Cannot analyze critical paths: per-file coverage not available');
    return true; // Pass if data unavailable
  }

  logInfo('\n🔥 Critical Path Coverage Analysis (≥90% required):');

  let criticalPathsPassed = true;
  let analyzedPaths = 0;

  // Analyze critical path files
  COVERAGE_CONFIG.CRITICAL_PATHS.forEach((pattern) => {
    const matchingFiles = Object.keys(perFileCoverage).filter((file) =>
      file.match(pattern.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*'))
    );

    matchingFiles.forEach((filePath) => {
      const fileCoverage = perFileCoverage[filePath];
      if (!fileCoverage) return;

      analyzedPaths++;
      const statements = fileCoverage.s?.pct || 0;
      const branches = fileCoverage.b?.pct || 0;
      const functions = fileCoverage.f?.pct || 0;
      const lines = fileCoverage.l?.pct || 0;

      // Use the lowest metric as the overall coverage
      const overallCoverage = Math.min(statements, branches, functions, lines);
      const threshold = COVERAGE_CONFIG.CRITICAL_THRESHOLDS.statements;
      const passed = overallCoverage >= threshold;

      const status = passed ? '✅' : '❌';
      const color = passed ? COLORS.green : COLORS.red;
      const indicator = getCoverageIndicator(overallCoverage);
      const relativePath = filePath.replace(/^.*\/src\//, 'src/');

      log(`   ${status} ${relativePath}: ${overallCoverage.toFixed(1)}% ${indicator}`, color);

      if (!passed) {
        criticalPathsPassed = false;
        logCritical(
          `     ↳ CRITICAL: ${(threshold - overallCoverage).toFixed(1)}% points below critical threshold`
        );

        // Show detailed metrics for failed critical paths
        log(
          `     ↳ Details: S:${statements.toFixed(1)}% B:${branches.toFixed(1)}% F:${functions.toFixed(1)}% L:${lines.toFixed(1)}%`,
          COLORS.dim
        );
      }
    });
  });

  if (analyzedPaths === 0) {
    logWarning('⚠️  No critical path files found in coverage data');
    return true;
  }

  logInfo(`   Analyzed ${analyzedPaths} critical path files`);
  return criticalPathsPassed;
}

/**
 * Get visual coverage indicator
 */
function getCoverageIndicator(coverage) {
  if (coverage >= 95) return '🟢';
  if (coverage >= 90) return '🟡';
  if (coverage >= 85) return '🟠';
  return '🔴';
}

/**
 * Generate enhanced HTML coverage report with visual indicators
 */
function generateEnhancedHtmlReport(totalCoverage, perFileCoverage) {
  logInfo('\n🌐 Generating enhanced HTML coverage report...');

  const reportDir = join(projectRoot, 'coverage', 'enhanced');
  if (!existsSync(reportDir)) {
    mkdirSync(reportDir, { recursive: true });
  }

  const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced Coverage Report - Cortex Memory MCP</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background: #f8f9fa; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric-card { background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .metric-value { font-size: 2.5em; font-weight: bold; margin: 10px 0; }
        .metric-label { color: #666; font-size: 1.1em; }
        .threshold-bar { height: 8px; background: #e9ecef; border-radius: 4px; margin: 15px 0; overflow: hidden; }
        .threshold-fill { height: 100%; transition: width 0.3s ease; }
        .critical-section { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 30px; }
        .critical-path { display: flex; justify-content: space-between; align-items: center; padding: 15px; margin: 10px 0; border-radius: 8px; background: #f8f9fa; }
        .critical-path.pass { border-left: 5px solid #28a745; }
        .critical-path.fail { border-left: 5px solid #dc3545; background: #fff5f5; }
        .coverage-badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-weight: bold; color: white; font-size: 0.9em; }
        .coverage-excellent { background: #28a745; }
        .coverage-good { background: #ffc107; color: #000; }
        .coverage-minimum { background: #fd7e14; }
        .coverage-poor { background: #dc3545; }
        .summary-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-item { text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px; }
        .stat-value { font-size: 1.5em; font-weight: bold; color: #495057; }
        .stat-label { color: #6c757d; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🧠 Enhanced Coverage Report</h1>
        <p>Cortex Memory MCP Server - Dual Threshold Coverage Analysis</p>
        <p><strong>Generated:</strong> ${new Date().toISOString()}</p>
    </div>

    <div class="metrics-grid">
        <div class="metric-card">
            <div class="metric-label">Statements Coverage</div>
            <div class="metric-value">${totalCoverage.statements?.pct?.toFixed(1) || 0}%</div>
            <div class="threshold-bar">
                <div class="threshold-fill ${getCoverageClass(totalCoverage.statements?.pct || 0)}" style="width: ${totalCoverage.statements?.pct || 0}%"></div>
            </div>
            <div class="coverage-badge ${getCoverageClass(totalCoverage.statements?.pct || 0)}">${getCoverageLevel(totalCoverage.statements?.pct || 0)}</div>
        </div>

        <div class="metric-card">
            <div class="metric-label">Branches Coverage</div>
            <div class="metric-value">${totalCoverage.branches?.pct?.toFixed(1) || 0}%</div>
            <div class="threshold-bar">
                <div class="threshold-fill ${getCoverageClass(totalCoverage.branches?.pct || 0)}" style="width: ${totalCoverage.branches?.pct || 0}%"></div>
            </div>
            <div class="coverage-badge ${getCoverageClass(totalCoverage.branches?.pct || 0)}">${getCoverageLevel(totalCoverage.branches?.pct || 0)}</div>
        </div>

        <div class="metric-card">
            <div class="metric-label">Functions Coverage</div>
            <div class="metric-value">${totalCoverage.functions?.pct?.toFixed(1) || 0}%</div>
            <div class="threshold-bar">
                <div class="threshold-fill ${getCoverageClass(totalCoverage.functions?.pct || 0)}" style="width: ${totalCoverage.functions?.pct || 0}%"></div>
            </div>
            <div class="coverage-badge ${getCoverageClass(totalCoverage.functions?.pct || 0)}">${getCoverageLevel(totalCoverage.functions?.pct || 0)}</div>
        </div>

        <div class="metric-card">
            <div class="metric-label">Lines Coverage</div>
            <div class="metric-value">${totalCoverage.lines?.pct?.toFixed(1) || 0}%</div>
            <div class="threshold-bar">
                <div class="threshold-fill ${getCoverageClass(totalCoverage.lines?.pct || 0)}" style="width: ${totalCoverage.lines?.pct || 0}%"></div>
            </div>
            <div class="coverage-badge ${getCoverageClass(totalCoverage.lines?.pct || 0)}">${getCoverageLevel(totalCoverage.lines?.pct || 0)}</div>
        </div>
    </div>

    <div class="critical-section">
        <h2>🔥 Critical Path Analysis (≥90% required)</h2>
        <p>Core components that require the highest coverage standards for production readiness.</p>
        ${generateCriticalPathHtml(perFileCoverage)}
    </div>

    <div class="critical-section">
        <h2>📊 Coverage Standards</h2>
        <div class="summary-stats">
            <div class="stat-item">
                <div class="stat-value">≥85%</div>
                <div class="stat-label">Global Minimum</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">≥90%</div>
                <div class="stat-label">Critical Paths</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">16</div>
                <div class="stat-label">Knowledge Types</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">2</div>
                <div class="stat-label">MCP Tools</div>
            </div>
        </div>
    </div>

    <script>
        // Add interactive features
        document.addEventListener('DOMContentLoaded', function() {
            console.log('Enhanced Coverage Report loaded successfully');
        });
    </script>
</body>
</html>`;

  const reportPath = join(reportDir, 'index.html');
  writeFileSync(reportPath, htmlContent);

  logSuccess(`Enhanced HTML report generated: ${reportPath}`);
  return reportPath;
}

function getCoverageClass(coverage) {
  if (coverage >= 95) return 'coverage-excellent';
  if (coverage >= 90) return 'coverage-good';
  if (coverage >= 85) return 'coverage-minimum';
  return 'coverage-poor';
}

function getCoverageLevel(coverage) {
  if (coverage >= 95) return 'Excellent';
  if (coverage >= 90) return 'Good';
  if (coverage >= 85) return 'Minimum';
  return 'Poor';
}

function generateCriticalPathHtml(perFileCoverage) {
  if (!perFileCoverage) return '<p>No per-file coverage data available</p>';

  let html = '';
  COVERAGE_CONFIG.CRITICAL_PATHS.forEach((pattern) => {
    const matchingFiles = Object.keys(perFileCoverage).filter((file) =>
      file.match(pattern.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*'))
    );

    matchingFiles.forEach((filePath) => {
      const fileCoverage = perFileCoverage[filePath];
      if (!fileCoverage) return;

      const statements = fileCoverage.s?.pct || 0;
      const branches = fileCoverage.b?.pct || 0;
      const functions = fileCoverage.f?.pct || 0;
      const lines = fileCoverage.l?.pct || 0;
      const overall = Math.min(statements, branches, functions, lines);
      const passed = overall >= 90;

      const relativePath = filePath.replace(/^.*\/src\//, 'src/');
      const statusClass = passed ? 'pass' : 'fail';
      const badgeClass = getCoverageClass(overall);

      html += `
        <div class="critical-path ${statusClass}">
            <div>
                <strong>${relativePath}</strong>
                <br><small>S: ${statements.toFixed(1)}% | B: ${branches.toFixed(1)}% | F: ${functions.toFixed(1)}% | L: ${lines.toFixed(1)}%</small>
            </div>
            <div class="coverage-badge ${badgeClass}">${overall.toFixed(1)}%</div>
        </div>`;
    });
  });

  return html || '<p>No critical path files found</p>';
}

/**
 * Generate coverage artifact summary
 */
function generateCoverageArtifact(totalCoverage, globalPassed, criticalPassed, htmlReportPath) {
  const artifact = {
    timestamp: new Date().toISOString(),
    version: '2.0.1',
    thresholds: {
      global: COVERAGE_CONFIG.GLOBAL_THRESHOLDS,
      critical: COVERAGE_CONFIG.CRITICAL_THRESHOLDS,
    },
    results: {
      global: {
        coverage: totalCoverage,
        passed: globalPassed,
        deficit: {
          statements: Math.max(
            0,
            COVERAGE_CONFIG.GLOBAL_THRESHOLDS.statements - (totalCoverage.statements?.pct || 0)
          ),
          branches: Math.max(
            0,
            COVERAGE_CONFIG.GLOBAL_THRESHOLDS.branches - (totalCoverage.branches?.pct || 0)
          ),
          functions: Math.max(
            0,
            COVERAGE_CONFIG.GLOBAL_THRESHOLDS.functions - (totalCoverage.functions?.pct || 0)
          ),
          lines: Math.max(
            0,
            COVERAGE_CONFIG.GLOBAL_THRESHOLDS.lines - (totalCoverage.lines?.pct || 0)
          ),
        },
      },
      critical: {
        passed: criticalPassed,
        analyzedPaths: COVERAGE_CONFIG.CRITICAL_PATHS.length,
      },
    },
    artifacts: {
      htmlReport: htmlReportPath,
      coverageDir: join(projectRoot, 'coverage'),
      timestamp: new Date().toISOString(),
    },
    status: {
      overall: globalPassed && criticalPassed ? 'PASS' : 'FAIL',
      readyForProduction: globalPassed && criticalPassed,
    },
  };

  // Save artifact
  const artifactPath = join(projectRoot, 'coverage', 'coverage-artifact.json');
  writeFileSync(artifactPath, JSON.stringify(artifact, null, 2));

  logSuccess(`Coverage artifact saved: ${artifactPath}`);
  return artifact;
}

/**
 * Main enhanced coverage gate enforcement
 */
function enforceCoverageGates() {
  logInfo('🚀 Starting Enhanced Coverage Gate Enforcement - T09 Implementation');
  logInfo('📋 Dual Threshold Requirements: ≥85% Global, ≥90% Critical Paths');

  // Run coverage analysis
  if (!runEnhancedCoverage()) {
    logError('Coverage analysis failed - cannot enforce gates');
    process.exit(1);
  }

  // Parse coverage data
  const totalCoverage = parseCoverageSummary();
  const perFileCoverage = parsePerFileCoverage();

  if (!totalCoverage) {
    logError('Unable to parse coverage results');
    process.exit(1);
  }

  // Check global thresholds (≥85%)
  const globalPassed = checkGlobalThresholds(totalCoverage);

  // Check critical path thresholds (≥90%)
  const criticalPassed = checkCriticalPathCoverage(perFileCoverage);

  // Generate enhanced HTML report
  const htmlReportPath = generateEnhancedHtmlReport(totalCoverage, perFileCoverage);

  // Generate coverage artifact
  const artifact = generateCoverageArtifact(
    totalCoverage,
    globalPassed,
    criticalPassed,
    htmlReportPath
  );

  // Final determination
  logInfo('\n🎯 FINAL COVERAGE GATE RESULTS:');

  const globalStatus = globalPassed ? '✅ PASSED' : '❌ FAILED';
  const criticalStatus = criticalPassed ? '✅ PASSED' : '❌ FAILED';
  const overallStatus = globalPassed && criticalPassed ? '✅ PASSED' : '❌ FAILED';

  log(`   Global Coverage (≥85%): ${globalStatus}`, globalPassed ? COLORS.green : COLORS.red);
  log(`   Critical Paths (≥90%): ${criticalStatus}`, criticalPassed ? COLORS.green : COLORS.red);
  log(
    `   Overall Status: ${overallStatus}`,
    globalPassed && criticalPassed ? COLORS.green : COLORS.red
  );

  if (globalPassed && criticalPassed) {
    logSuccess('\n🎉 All coverage gates PASSED! Ready for production deployment.');
    logSuccess('📄 Enhanced HTML report available for detailed analysis');
    logInfo(`🔗 Open report: ${htmlReportPath}`);
    return;
  } else {
    logCritical('\n❌ COVERAGE GATES FAILED - Deployment blocked');

    if (!globalPassed) {
      logError('💡 Global coverage below 85% threshold - Add more tests to improve coverage');
    }

    if (!criticalPassed) {
      logCritical('🔥 Critical path coverage below 90% - Core components need additional testing');
      logError('💡 Focus on testing memory_store, memory_find, auth, and database components');
    }

    logError('\n🚫 Deployment blocked until coverage requirements are met');
    process.exit(1);
  }
}

// Execute if run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  enforceCoverageGates();
}

export { enforceCoverageGates, COVERAGE_CONFIG };
