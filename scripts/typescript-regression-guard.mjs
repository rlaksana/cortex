#!/usr/bin/env node

/**
 * TypeScript Regression Guard
 *
 * Prevents TypeScript error count increases and enforces quality gates.
 * Integrates with CI/CD pipelines to maintain code quality standards.
 *
 * @version 1.0.0
 * @since 2025-11-07
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { execSync } from 'child_process';

const REGRESSION_THRESHOLD = 50; // Target <50 errors
const BASELINE_FILE = 'artifacts/ts-errors-baseline.txt';
const REPORT_FILE = 'artifacts/ts-regression-report.json';
const ERROR_COUNT_PATTERN = /Found (\d+) errors/;

interface RegressionMetrics {
  timestamp: string;
  totalErrors: number;
  baselineErrors?: number;
  errorDelta: number;
  regressionDetected: boolean;
  buildTime?: number;
  errorMessage?: string;
  filesByErrorCount: Array<{ file: string; errors: number }>;
  topErrorCodes: Array<{ code: string; count: string }>;
}

class TypeScriptRegressionGuard {
  constructor() {
    this.ensureArtifactDirectory();
  }

  /**
   * Main execution method
   */
  async run() {
    try {
      console.log('🔍 TypeScript Regression Guard - Starting analysis...');

      const metrics = await this.generateMetrics();
      await this.saveReport(metrics);

      if (metrics.regressionDetected) {
        this.handleRegression(metrics);
        process.exit(1);
      }

      this.reportSuccess(metrics);
      process.exit(0);
    } catch (error) {
      console.error('❌ TypeScript Regression Guard failed:', error.message);
      process.exit(1);
    }
  }

  /**
   * Generate comprehensive metrics
   */
  async generateMetrics(): Promise<RegressionMetrics> {
    const startTime = Date.now();

    // Run TypeScript compilation
    const tscOutput = this.runTypeScriptCheck();

    // Parse error count
    const totalErrors = this.parseErrorCount(tscOutput);

    // Get baseline if exists
    const baselineErrors = this.getBaselineErrors();

    // Calculate delta
    const errorDelta = totalErrors - (baselineErrors || 0);

    // Analyze error distribution
    const filesByErrorCount = this.analyzeErrorFiles(tscOutput);
    const topErrorCodes = this.analyzeErrorCodes(tscOutput);

    const buildTime = Date.now() - startTime;

    return {
      timestamp: new Date().toISOString(),
      totalErrors,
      baselineErrors,
      errorDelta,
      regressionDetected: totalErrors > REGRESSION_THRESHOLD || errorDelta > 10,
      buildTime,
      filesByErrorCount,
      topErrorCodes
    };
  }

  /**
   * Run TypeScript compilation check
   */
  runTypeScriptCheck(): string {
    try {
      const output = execSync('npx tsc --noEmit --pretty false', {
        encoding: 'utf8',
        stdio: 'pipe'
      });
      return output;
    } catch (error) {
      // TypeScript exits with error code when errors found - this is expected
      return error.stdout || error.message;
    }
  }

  /**
   * Parse error count from TypeScript output
   */
  parseErrorCount(output: string): number {
    const match = output.match(ERROR_COUNT_PATTERN);
    if (match) {
      return parseInt(match[1], 10);
    }

    // Alternative parsing for different TypeScript versions
    const lines = output.split('\n');
    for (const line of lines) {
      if (line.includes('errors') && /\d+/.test(line)) {
        const numbers = line.match(/\d+/g);
        if (numbers && numbers.length > 0) {
          return parseInt(numbers[0], 10);
        }
      }
    }

    // Count error lines as fallback
    const errorLines = output.split('\n').filter(line => line.includes('error TS'));
    return errorLines.length;
  }

  /**
   * Get baseline error count
   */
  getBaselineErrors(): number | null {
    if (!existsSync(BASELINE_FILE)) {
      console.warn(`⚠️  Baseline file not found: ${BASELINE_FILE}`);
      return null;
    }

    try {
      const content = readFileSync(BASELINE_FILE, 'utf8');
      const match = content.match(/Total:\s*(\d+)/);
      return match ? parseInt(match[1], 10) : null;
    } catch (error) {
      console.warn(`⚠️  Could not read baseline file: ${error.message}`);
      return null;
    }
  }

  /**
   * Analyze errors by file
   */
  analyzeErrorFiles(output: string): Array<{ file: string; errors: number }> {
    const fileErrors = new Map<string, number>();

    const lines = output.split('\n');
    for (const line of lines) {
      // Match patterns like "src/file.ts(line,col): error TS1234: message"
      const match = line.match(/^([^(]+)\(\d+,\d+\):\s*error/);
      if (match) {
        const file = match[1];
        fileErrors.set(file, (fileErrors.get(file) || 0) + 1);
      }
    }

    return Array.from(fileErrors.entries())
      .map(([file, errors]) => ({ file, errors }))
      .sort((a, b) => b.errors - a.errors)
      .slice(0, 20); // Top 20 files
  }

  /**
   * Analyze top error codes
   */
  analyzeErrorCodes(output: string): Array<{ code: string; count: string }> {
    const errorCodes = new Map<string, number>();

    const lines = output.split('\n');
    for (const line of lines) {
      // Match patterns like "error TS1234"
      const match = line.match(/error TS(\d+)/);
      if (match) {
        const code = `TS${match[1]}`;
        errorCodes.set(code, (errorCodes.get(code) || 0) + 1);
      }
    }

    return Array.from(errorCodes.entries())
      .map(([code, count]) => ({ code, count: count.toString() }))
      .sort((a, b) => parseInt(b.count) - parseInt(a.count))
      .slice(0, 10); // Top 10 error codes
  }

  /**
   * Save detailed report
   */
  async saveReport(metrics: RegressionMetrics) {
    const report = {
      ...metrics,
      summary: this.generateSummary(metrics),
      recommendations: this.generateRecommendations(metrics)
    };

    writeFileSync(REPORT_FILE, JSON.stringify(report, null, 2));
    console.log(`📊 Regression report saved to: ${REPORT_FILE}`);
  }

  /**
   * Generate human-readable summary
   */
  generateSummary(metrics: RegressionMetrics): string {
    const { totalErrors, baselineErrors, errorDelta, buildTime } = metrics;

    let summary = `TypeScript Error Analysis:\n`;
    summary += `- Current Errors: ${totalErrors}\n`;

    if (baselineErrors !== null) {
      summary += `- Baseline Errors: ${baselineErrors}\n`;
      summary += `- Error Delta: ${errorDelta > 0 ? '+' : ''}${errorDelta}\n`;
    }

    summary += `- Regression Threshold: ${REGRESSION_THRESHOLD}\n`;
    summary += `- Build Time: ${buildTime}ms\n`;
    summary += `- Status: ${metrics.regressionDetected ? '❌ REGRESSION DETECTED' : '✅ PASSED'}`;

    return summary;
  }

  /**
   * Generate actionable recommendations
   */
  generateRecommendations(metrics: RegressionMetrics): string[] {
    const recommendations = [];

    if (metrics.totalErrors > REGRESSION_THRESHOLD) {
      recommendations.push(`Total errors (${metrics.totalErrors}) exceed threshold (${REGRESSION_THRESHOLD})`);
    }

    if (metrics.errorDelta > 10) {
      recommendations.push(`Error count increased by ${metrics.errorDelta} - investigate recent changes`);
    }

    // Analyze top error files
    const topFile = metrics.filesByErrorCount[0];
    if (topFile && topFile.errors > 20) {
      recommendations.push(`File ${topFile} has ${topFile.errors} errors - prioritize fixing this file`);
    }

    // Analyze top error codes
    const topErrorCode = metrics.topErrorCodes[0];
    if (topErrorCode && parseInt(topErrorCode.count) > 10) {
      recommendations.push(`Error code ${topErrorCode.code} occurs ${topErrorCode.count} times - consider automated fixes`);
    }

    if (metrics.buildTime && metrics.buildTime > 60000) {
      recommendations.push(`Build time (${metrics.buildTime}ms) exceeds 60s - consider TypeScript optimization`);
    }

    if (recommendations.length === 0) {
      recommendations.push('No major issues detected - continue maintaining code quality');
    }

    return recommendations;
  }

  /**
   * Handle regression detection
   */
  handleRegression(metrics: RegressionMetrics) {
    console.log('\n❌ TypeScript Regression Detected!');
    console.log(this.generateSummary(metrics));

    console.log('\n📋 Top Recommendations:');
    metrics.recommendations.forEach((rec, index) => {
      console.log(`${index + 1}. ${rec}`);
    });

    if (metrics.filesByErrorCount.length > 0) {
      console.log('\n📂 Files with Most Errors:');
      metrics.filesByErrorCount.slice(0, 5).forEach(({ file, errors }) => {
        console.log(`   ${file}: ${errors} errors`);
      });
    }

    if (metrics.topErrorCodes.length > 0) {
      console.log('\n🔍 Top Error Codes:');
      metrics.topErrorCodes.slice(0, 5).forEach(({ code, count }) => {
        console.log(`   ${code}: ${count} occurrences`);
      });
    }
  }

  /**
   * Report successful validation
   */
  reportSuccess(metrics: RegressionMetrics) {
    console.log('\n✅ TypeScript Regression Guard - PASSED');
    console.log(this.generateSummary(metrics));

    if (metrics.recommendations.length > 0) {
      console.log('\n💡 Recommendations:');
      metrics.recommendations.forEach(rec => console.log(`   ${rec}`));
    }
  }

  /**
   * Ensure artifact directory exists
   */
  ensureArtifactDirectory() {
    const artifactDir = dirname(REPORT_FILE);
    if (!existsSync(artifactDir)) {
      mkdirSync(artifactDir, { recursive: true });
    }
  }

  /**
   * Set new baseline
   */
  static setBaseline() {
    console.log('📝 Setting new TypeScript error baseline...');

    try {
      const output = execSync('npx tsc --noEmit --pretty false', {
        encoding: 'utf8',
        stdio: 'pipe'
      });

      const errorCount = new TypeScriptRegressionGuard().parseErrorCount(output);

      // Ensure artifact directory exists
      const artifactDir = dirname(BASELINE_FILE);
      if (!existsSync(artifactDir)) {
        mkdirSync(artifactDir, { recursive: true });
      }

      const baselineContent = `TypeScript Error Baseline\nGenerated: ${new Date().toISOString()}\nTotal: ${errorCount}\n`;
      writeFileSync(BASELINE_FILE, baselineContent);

      console.log(`✅ Baseline set to ${errorCount} errors`);
      console.log(`📄 Baseline saved to: ${BASELINE_FILE}`);
    } catch (error) {
      console.error('❌ Failed to set baseline:', error.message);
      process.exit(1);
    }
  }
}

// CLI interface
if (import.meta.url === `file://${process.argv[1]}`) {
  const command = process.argv[2];

  if (command === '--set-baseline') {
    TypeScriptRegressionGuard.setBaseline();
  } else {
    const guard = new TypeScriptRegressionGuard();
    guard.run();
  }
}

export default TypeScriptRegressionGuard;