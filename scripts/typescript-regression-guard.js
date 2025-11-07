#!/usr/bin/env node

/**
 * TypeScript Regression Guard
 *
 * Prevents TypeScript error count increases in CI/CD pipeline
 * Integrates with existing performance monitoring and SLO infrastructure
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { performance } = require('perf_hooks');

class TypeScriptRegressionGuard {
  constructor(options = {}) {
    this.options = {
      // Error budget thresholds
      maxErrorIncrease: options.maxErrorIncrease || 0, // Zero tolerance for new errors
      maxErrorRegressionPercent: options.maxErrorRegressionPercent || 10,
      criticalErrorCodes: options.criticalErrorCodes || new Set([2307, 2322, 2339, 2345, 2352]),
      warningErrorCodes: options.warningErrorCodes || new Set([18048, 7005, 7006, 7016]),

      // Baseline management
      baselineFile: options.baselineFile || '.artifacts/typescript-baseline.json',
      reportDir: options.reportDir || 'artifacts/typescript-regression',

      // Integration settings
      enableRollback: options.enableRollback !== false,
      enablePRBlocking: options.enablePRBlocking !== false,

      ...options
    };

    this.currentMetrics = null;
    this.baselineMetrics = null;
    this.reportData = {};
  }

  /**
   * Execute full regression guard workflow
   */
  async execute() {
    console.log('🛡️ TypeScript Regression Guard - Starting analysis');

    try {
      // Ensure directories exist
      this.ensureDirectories();

      // Load baseline data
      this.loadBaseline();

      // Analyze current TypeScript errors
      this.analyzeCurrentErrors();

      // Compare against baseline and detect regressions
      this.detectRegressions();

      // Generate regression report
      this.generateReport();

      // Determine CI outcome
      return this.evaluateCIOutcome();

    } catch (error) {
      console.error('❌ TypeScript Regression Guard failed:', error.message);
      return { success: false, error: error.message, blocked: true };
    }
  }

  /**
   * Ensure artifact directories exist
   */
  ensureDirectories() {
    const dirs = [
      this.options.reportDir,
      path.dirname(this.options.baselineFile),
      'artifacts/typescript-regression/reports',
      'artifacts/typescript-regression/metrics'
    ];

    dirs.forEach(dir => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    });
  }

  /**
   * Load baseline TypeScript metrics
   */
  loadBaseline() {
    const baselinePath = this.options.baselineFile;

    if (fs.existsSync(baselinePath)) {
      try {
        const baselineData = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
        this.baselineMetrics = baselineData.metrics;
        this.reportData.baselineLoaded = true;
        console.log(`✅ Loaded baseline from ${baselinePath}`);
      } catch (error) {
        console.warn(`⚠️ Failed to load baseline: ${error.message}`);
        this.baselineMetrics = this.createFallbackBaseline();
        this.reportData.baselineLoaded = false;
      }
    } else {
      console.log('ℹ️ No baseline found - will create one after this run');
      this.baselineMetrics = this.createFallbackBaseline();
      this.reportData.baselineLoaded = false;
    }
  }

  /**
   * Create fallback baseline for first run
   */
  createFallbackBaseline() {
    return {
      timestamp: new Date().toISOString(),
      totalErrors: 0,
      errorsByCode: {},
      errorsByFile: {},
      criticalErrors: 0,
      warningErrors: 0,
      buildTime: 0,
      buildSuccess: true
    };
  }

  /**
   * Analyze current TypeScript errors
   */
  analyzeCurrentErrors() {
    console.log('🔍 Analyzing current TypeScript compilation...');

    const startTime = performance.now();

    try {
      // Run TypeScript compiler with diagnostics
      const output = execSync('npx tsc --noEmit --pretty false --diagnostics', {
        encoding: 'utf8',
        stdio: 'pipe'
      });

      // Extract performance metrics from diagnostics
      const diagnosticLines = output.split('\n');
      const buildTimeMatch = diagnosticLines.find(line => line.includes('Time:'));
      const buildTime = buildTimeMatch ? this.extractTimeFromDiagnostic(buildTimeMatch) : 0;

      // Run TypeScript compiler to get errors
      const errorOutput = execSync('npx tsc --noEmit --pretty false', {
        encoding: 'utf8',
        stdio: 'pipe'
      });

      const endTime = performance.now();
      const totalBuildTime = endTime - startTime;

      // Parse errors
      const errors = this.parseTypeScriptErrors(errorOutput);
      const metrics = this.calculateMetrics(errors, totalBuildTime, buildTime);

      this.currentMetrics = metrics;
      this.reportData.analysisSuccessful = true;

      console.log(`✅ TypeScript analysis complete: ${metrics.totalErrors} errors found`);

    } catch (error) {
      // TypeScript compilation failed - parse errors from stderr
      const errorOutput = error.stderr || error.stdout || '';
      const errors = this.parseTypeScriptErrors(errorOutput);
      const endTime = performance.now();
      const totalBuildTime = endTime - startTime;

      this.currentMetrics = this.calculateMetrics(errors, totalBuildTime, 0, false);
      this.reportData.analysisSuccessful = false;

      console.log(`⚠️ TypeScript compilation failed: ${this.currentMetrics.totalErrors} errors`);
    }
  }

  /**
   * Extract time from TypeScript diagnostic output
   */
  extractTimeFromDiagnostic(line) {
    const match = line.match(/Time:\s*(\d+)ms/);
    return match ? parseInt(match[1]) : 0;
  }

  /**
   * Parse TypeScript errors from compiler output
   */
  parseTypeScriptErrors(output) {
    const errors = [];
    const lines = output.split('\n');

    for (const line of lines) {
      if (line.trim() && !line.startsWith('npm') && !line.includes('node_modules')) {
        const match = line.match(/^(.+?)\((\d+),(\d+)\):\s+error\s+(TS\d+):\s+(.+)$/);
        if (match) {
          errors.push({
            file: match[1].trim(),
            line: parseInt(match[2]),
            column: parseInt(match[3]),
            code: match[4].replace('TS', ''),
            message: match[5].trim()
          });
        }
      }
    }

    return errors;
  }

  /**
   * Calculate metrics from error analysis
   */
  calculateMetrics(errors, totalBuildTime, compilerBuildTime, buildSuccess = true) {
    const errorsByCode = {};
    const errorsByFile = {};
    let criticalErrors = 0;
    let warningErrors = 0;

    for (const error of errors) {
      // Count by error code
      errorsByCode[error.code] = (errorsByCode[error.code] || 0) + 1;

      // Count by file
      const relativeFile = path.relative(process.cwd(), error.file);
      errorsByFile[relativeFile] = (errorsByFile[relativeFile] || 0) + 1;

      // Categorize errors
      if (this.options.criticalErrorCodes.has(parseInt(error.code))) {
        criticalErrors++;
      } else if (this.options.warningErrorCodes.has(parseInt(error.code))) {
        warningErrors++;
      }
    }

    return {
      timestamp: new Date().toISOString(),
      totalErrors: errors.length,
      errorsByCode,
      errorsByFile,
      criticalErrors,
      warningErrors,
      buildTime: totalBuildTime,
      compilerBuildTime,
      buildSuccess,
      errors // Keep raw errors for detailed analysis
    };
  }

  /**
   * Detect regressions by comparing current vs baseline
   */
  detectRegressions() {
    if (!this.baselineMetrics || !this.currentMetrics) {
      this.reportData.regressions = { detected: false, reason: 'No baseline or current metrics' };
      return;
    }

    const regressions = {
      detected: false,
      errorIncrease: 0,
      errorRegressionPercent: 0,
      newErrorCodes: [],
      increasedErrorCodes: [],
      criticalRegressions: [],
      performanceRegression: false,
      details: {}
    };

    // Check total error increase
    const errorIncrease = this.currentMetrics.totalErrors - this.baselineMetrics.totalErrors;
    regressions.errorIncrease = errorIncrease;

    if (errorIncrease > this.options.maxErrorIncrease) {
      regressions.detected = true;
      regressions.details.totalErrorIncrease = {
        baseline: this.baselineMetrics.totalErrors,
        current: this.currentMetrics.totalErrors,
        increase: errorIncrease
      };
    }

    // Check percentage regression
    if (this.baselineMetrics.totalErrors > 0) {
      const regressionPercent = (errorIncrease / this.baselineMetrics.totalErrors) * 100;
      regressions.errorRegressionPercent = regressionPercent;

      if (regressionPercent > this.options.maxErrorRegressionPercent) {
        regressions.detected = true;
        regressions.details.percentageRegression = {
          baseline: this.baselineMetrics.totalErrors,
          current: this.currentMetrics.totalErrors,
          percent: regressionPercent.toFixed(2)
        };
      }
    }

    // Check for new error codes
    const baselineCodes = new Set(Object.keys(this.baselineMetrics.errorsByCode));
    const currentCodes = new Set(Object.keys(this.currentMetrics.errorsByCode));

    for (const code of currentCodes) {
      if (!baselineCodes.has(code)) {
        regressions.newErrorCodes.push(code);
        regressions.detected = true;
      }
    }

    // Check for increased error codes
    for (const [code, count] of Object.entries(this.currentMetrics.errorsByCode)) {
      const baselineCount = this.baselineMetrics.errorsByCode[code] || 0;
      if (count > baselineCount) {
        regressions.increasedErrorCodes.push({
          code,
          baseline: baselineCount,
          current: count,
          increase: count - baselineCount
        });

        // Critical error regressions
        if (this.options.criticalErrorCodes.has(parseInt(code))) {
          regressions.criticalRegressions.push(code);
        }
      }
    }

    // Check performance regression (build time)
    if (this.baselineMetrics.buildTime > 0 && this.currentMetrics.buildTime > 0) {
      const buildTimeIncrease = (this.currentMetrics.buildTime / this.baselineMetrics.buildTime - 1) * 100;
      if (buildTimeIncrease > 50) { // 50% increase threshold
        regressions.performanceRegression = true;
        regressions.detected = true;
        regressions.details.buildTimeRegression = {
          baseline: this.baselineMetrics.buildTime,
          current: this.currentMetrics.buildTime,
          increasePercent: buildTimeIncrease.toFixed(2)
        };
      }
    }

    this.reportData.regressions = regressions;

    if (regressions.detected) {
      console.log('🚨 TypeScript regressions detected');
    } else {
      console.log('✅ No TypeScript regressions detected');
    }
  }

  /**
   * Generate comprehensive regression report
   */
  generateReport() {
    const report = {
      timestamp: new Date().toISOString(),
      guardVersion: '1.0.0',
      options: this.options,
      baselineMetrics: this.baselineMetrics,
      currentMetrics: this.currentMetrics,
      regressions: this.reportData.regressions,
      summary: this.generateSummary(),
      recommendations: this.generateRecommendations()
    };

    // Save JSON report
    const reportPath = path.join(this.options.reportDir, 'typescript-regression-report.json');
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

    // Generate HTML report
    this.generateHTMLReport(report);

    // Generate CSV metrics
    this.generateCSVMetrics();

    console.log(`📊 Regression report saved to ${reportPath}`);
  }

  /**
   * Generate summary statistics
   */
  generateSummary() {
    const summary = {
      totalErrors: this.currentMetrics?.totalErrors || 0,
      baselineErrors: this.baselineMetrics?.totalErrors || 0,
      errorDelta: (this.currentMetrics?.totalErrors || 0) - (this.baselineMetrics?.totalErrors || 0),
      buildTime: this.currentMetrics?.buildTime || 0,
      regressionsDetected: this.reportData.regressions?.detected || false,
      newErrorCodesCount: this.reportData.regressions?.newErrorCodes?.length || 0,
      criticalErrors: this.currentMetrics?.criticalErrors || 0,
      warningErrors: this.currentMetrics?.warningErrors || 0
    };

    return summary;
  }

  /**
   * Generate actionable recommendations
   */
  generateRecommendations() {
    const recommendations = [];

    if (!this.reportData.regressions?.detected) {
      recommendations.push({
        type: 'success',
        priority: 'info',
        title: 'No Regressions Detected',
        description: 'TypeScript metrics are within acceptable limits'
      });
      return recommendations;
    }

    const regressions = this.reportData.regressions;

    // Total error increase recommendations
    if (regressions.errorIncrease > 0) {
      recommendations.push({
        type: 'error',
        priority: 'high',
        title: `Error Count Increased by ${regressions.errorIncrease}`,
        description: `Total errors increased from ${this.baselineMetrics.totalErrors} to ${this.currentMetrics.totalErrors}`,
        action: 'Review and fix new TypeScript errors before proceeding'
      });
    }

    // New error codes
    if (regressions.newErrorCodes.length > 0) {
      recommendations.push({
        type: 'error',
        priority: 'high',
        title: `New Error Codes Detected: ${regressions.newErrorCodes.join(', ')}`,
        description: 'These error codes were not present in the baseline',
        action: 'Investigate and resolve the root cause of new error types'
      });
    }

    // Critical regressions
    if (regressions.criticalRegressions.length > 0) {
      recommendations.push({
        type: 'error',
        priority: 'critical',
        title: `Critical Error Regressions: ${regressions.criticalRegressions.join(', ')}`,
        description: 'Critical error types have increased in count',
        action: 'Address these critical errors immediately as they may impact runtime behavior'
      });
    }

    // Performance regression
    if (regressions.performanceRegression) {
      recommendations.push({
        type: 'warning',
        priority: 'medium',
        title: 'Build Time Regression Detected',
        description: `Build time increased significantly from baseline`,
        action: 'Consider optimizing type checking, splitting into smaller projects, or reviewing recent changes'
      });
    }

    return recommendations;
  }

  /**
   * Generate HTML report for better visualization
   */
  generateHTMLReport(report) {
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TypeScript Regression Guard Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f8f9fa; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 2px solid #e9ecef; }
        .status { display: inline-block; padding: 8px 16px; border-radius: 20px; font-weight: bold; margin: 10px 0; }
        .status.pass { background: #d4edda; color: #155724; }
        .status.fail { background: #f8d7da; color: #721c24; }
        .status.warning { background: #fff3cd; color: #856404; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
        .metric { padding: 20px; border: 1px solid #dee2e6; border-radius: 8px; text-align: center; }
        .metric-value { font-size: 2em; font-weight: bold; margin-bottom: 10px; }
        .metric-label { color: #6c757d; }
        .section { margin: 30px 0; }
        .section h2 { color: #495057; border-bottom: 2px solid #e9ecef; padding-bottom: 10px; }
        .recommendations { margin-top: 20px; }
        .recommendation { padding: 15px; margin: 10px 0; border-left: 4px solid; border-radius: 4px; }
        .recommendation.error { border-left-color: #dc3545; background: #f8d7da; }
        .recommendation.warning { border-left-color: #ffc107; background: #fff3cd; }
        .recommendation.success { border-left-color: #28a745; background: #d4edda; }
        .table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .table th, .table td { padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }
        .table th { background: #f8f9fa; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ TypeScript Regression Guard Report</h1>
            <p>Generated: ${report.timestamp}</p>
            <div class="status ${report.regressions.detected ? 'fail' : 'pass'}">
                ${report.regressions.detected ? '🚨 Regressions Detected' : '✅ No Regressions'}
            </div>
        </div>

        <div class="metrics">
            <div class="metric">
                <div class="metric-value">${report.summary.totalErrors}</div>
                <div class="metric-label">Total Errors</div>
            </div>
            <div class="metric">
                <div class="metric-value">${report.summary.errorDelta > 0 ? '+' : ''}${report.summary.errorDelta}</div>
                <div class="metric-label">Error Delta</div>
            </div>
            <div class="metric">
                <div class="metric-value">${report.summary.criticalErrors}</div>
                <div class="metric-label">Critical Errors</div>
            </div>
            <div class="metric">
                <div class="metric-value">${(report.summary.buildTime / 1000).toFixed(1)}s</div>
                <div class="metric-label">Build Time</div>
            </div>
        </div>

        <div class="section">
            <h2>📊 Error Breakdown</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Error Code</th>
                        <th>Current Count</th>
                        <th>Baseline Count</th>
                        <th>Change</th>
                    </tr>
                </thead>
                <tbody>
                    ${Object.entries(report.currentMetrics.errorsByCode || {})
                      .map(([code, count]) => {
                        const baseline = report.baselineMetrics.errorsByCode[code] || 0;
                        const change = count - baseline;
                        return `
                          <tr>
                            <td>TS${code}</td>
                            <td>${count}</td>
                            <td>${baseline}</td>
                            <td style="color: ${change > 0 ? '#dc3545' : '#28a745'}">
                              ${change > 0 ? '+' : ''}${change}
                            </td>
                          </tr>
                        `;
                      }).join('')}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>💡 Recommendations</h2>
            <div class="recommendations">
                ${report.recommendations.map(rec => `
                  <div class="recommendation ${rec.type}">
                    <h4>${rec.title}</h4>
                    <p>${rec.description}</p>
                    ${rec.action ? `<p><strong>Action:</strong> ${rec.action}</p>` : ''}
                  </div>
                `).join('')}
            </div>
        </div>
    </div>
</body>
</html>`;

    const htmlPath = path.join(this.options.reportDir, 'typescript-regression-report.html');
    fs.writeFileSync(htmlPath, html);
  }

  /**
   * Generate CSV metrics for tracking
   */
  generateCSVMetrics() {
    const csvPath = path.join(this.options.reportDir, 'metrics.csv');
    const isNew = !fs.existsSync(csvPath);

    const row = [
      this.currentMetrics.timestamp,
      this.currentMetrics.totalErrors,
      this.baselineMetrics.totalErrors,
      this.reportData.regressions.errorIncrease,
      this.currentMetrics.criticalErrors,
      this.currentMetrics.warningErrors,
      this.currentMetrics.buildTime,
      this.reportData.regressions.detected ? 'true' : 'false'
    ];

    const csvLine = row.join(',') + '\n';

    if (isNew) {
      const header = 'timestamp,total_errors,baseline_errors,error_increase,critical_errors,warning_errors,build_time,regressions_detected\n';
      fs.writeFileSync(csvPath, header + csvLine);
    } else {
      fs.appendFileSync(csvPath, csvLine);
    }
  }

  /**
   * Evaluate CI outcome and determine if build should be blocked
   */
  evaluateCIOutcome() {
    const regressions = this.reportData.regressions;
    let blocked = false;
    let reason = '';

    if (regressions?.detected) {
      // Block on any error increase if strict mode
      if (regressions.errorIncrease > this.options.maxErrorIncrease) {
        blocked = true;
        reason = `Error count increased by ${regressions.errorIncrease}`;
      }

      // Block on new critical error codes
      if (regressions.newErrorCodes.some(code => this.options.criticalErrorCodes.has(parseInt(code)))) {
        blocked = true;
        reason = reason ? `${reason}; new critical error codes detected` : 'New critical error codes detected';
      }

      // Block on critical regressions
      if (regressions.criticalRegressions.length > 0) {
        blocked = true;
        reason = reason ? `${reason}; critical error regressions` : 'Critical error regressions detected';
      }
    }

    // Update baseline if no regressions and baseline was not loaded
    if (!blocked && !this.reportData.baselineLoaded && this.currentMetrics) {
      this.updateBaseline();
    }

    const outcome = {
      success: !blocked,
      blocked,
      reason,
      metrics: this.currentMetrics,
      regressions: regressions,
      reportPath: path.join(this.options.reportDir, 'typescript-regression-report.json')
    };

    console.log(blocked ? '🚫 Build blocked by TypeScript regression guard' : '✅ TypeScript regression guard passed');
    if (reason) {
      console.log(`Reason: ${reason}`);
    }

    return outcome;
  }

  /**
   * Update baseline with current metrics
   */
  updateBaseline() {
    const baselineData = {
      timestamp: new Date().toISOString(),
      guardVersion: '1.0.0',
      metrics: this.currentMetrics
    };

    fs.writeFileSync(this.options.baselineFile, JSON.stringify(baselineData, null, 2));
    console.log(`📝 Updated baseline: ${this.options.baselineFile}`);
  }
}

// CLI execution
if (require.main === module) {
  const args = process.argv.slice(2);
  const options = {};

  // Parse command line arguments
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--max-error-increase':
        options.maxErrorIncrease = parseInt(args[++i]);
        break;
      case '--max-regression-percent':
        options.maxErrorRegressionPercent = parseFloat(args[++i]);
        break;
      case '--baseline-file':
        options.baselineFile = args[++i];
        break;
      case '--report-dir':
        options.reportDir = args[++i];
        break;
      case '--no-rollback':
        options.enableRollback = false;
        break;
      case '--no-pr-blocking':
        options.enablePRBlocking = false;
        break;
    }
  }

  const guard = new TypeScriptRegressionGuard(options);
  guard.execute()
    .then(outcome => {
      if (outcome.blocked) {
        console.error('Build blocked:', outcome.reason);
        process.exit(1);
      } else {
        console.log('✅ TypeScript regression guard passed');
        process.exit(0);
      }
    })
    .catch(error => {
      console.error('TypeScript regression guard failed:', error);
      process.exit(1);
    });
}

module.exports = TypeScriptRegressionGuard;