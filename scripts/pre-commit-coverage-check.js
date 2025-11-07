#!/usr/bin/env node

/**
 * Pre-commit Coverage Validation Script
 * Validates that coverage meets ≥85% thresholds before allowing commits
 * Integrates with pre-commit hooks to enforce coverage gates
 */

import fs from 'fs/promises';
import path from 'path';
import { execSync } from 'child_process';

class PreCommitCoverageValidator {
  constructor() {
    this.projectRoot = process.cwd();
    this.coverageDir = path.join(this.projectRoot, 'coverage');
    this.thresholds = {
      global: {
        statements: 85,
        branches: 85,
        functions: 85,
        lines: 85,
      },
    };
    this.allowSkip =
      process.argv.includes('--skip-coverage') || process.env.SKIP_COVERAGE_CHECK === 'true';
  }

  async init() {
    console.log('🔍 Running Pre-commit Coverage Validation...');

    if (this.allowSkip) {
      console.log(
        '⚠️  Coverage check skipped via --skip-coverage flag or SKIP_COVERAGE_CHECK env var'
      );
      return true;
    }

    try {
      await this.checkStagedFiles();
      await this.runCoverageTests();
      await this.validateCoverage();
      await this.generatePreCommitReport();

      console.log('✅ Pre-commit coverage validation passed!');
      console.log('🎯 All coverage thresholds (≥85%) are satisfied.');
      return true;
    } catch (error) {
      console.error('❌ Pre-commit coverage validation failed!');
      console.error('🚫 Commit blocked due to insufficient coverage.');
      console.error('');
      console.error('To skip coverage check (not recommended):');
      console.error('  git commit --no-verify');
      console.error('  or run with: --skip-coverage');
      console.error('');
      console.error('To fix coverage issues:');
      console.error('  1. Run: npm run test:coverage:ci');
      console.error('  2. Review coverage reports in coverage/comprehensive/');
      console.error('  3. Add tests for uncovered code');
      console.error('  4. Re-run validation');

      return false;
    }
  }

  async checkStagedFiles() {
    console.log('📋 Checking for staged TypeScript files...');

    try {
      const stagedFiles = execSync('git diff --cached --name-only --diff-filter=ACM', {
        encoding: 'utf8',
      })
        .trim()
        .split('\n')
        .filter((file) => file.endsWith('.ts') && file.startsWith('src/'));

      if (stagedFiles.length === 0) {
        console.log('ℹ️  No TypeScript files staged, skipping coverage check');
        process.exit(0);
      }

      console.log(`📝 Found ${stagedFiles.length} staged TypeScript files:`);
      stagedFiles.forEach((file) => console.log(`   - ${file}`));

      this.stagedFiles = stagedFiles;
    } catch (error) {
      console.warn('⚠️  Could not check staged files:', error.message);
    }
  }

  async runCoverageTests() {
    console.log('🧪 Running coverage tests...');

    try {
      // Run comprehensive coverage tests
      execSync('npm run test:coverage:ci', {
        stdio: 'pipe',
        cwd: this.projectRoot,
      });
      console.log('✅ Coverage tests completed');
    } catch (error) {
      console.error('❌ Coverage tests failed:', error.message);
      throw new Error('Coverage tests failed');
    }
  }

  async validateCoverage() {
    console.log('📊 Validating coverage against ≥85% thresholds...');

    const coverageSummaryPath = path.join(
      this.coverageDir,
      'comprehensive',
      'coverage-summary.json'
    );

    if (!(await this.fileExists(coverageSummaryPath))) {
      throw new Error('Coverage summary file not found. Run coverage tests first.');
    }

    const coverageData = JSON.parse(await fs.readFile(coverageSummaryPath, 'utf8'));
    const coverage = coverageData.total;

    console.log('📈 Coverage Results:');

    let allThresholdsMet = true;
    const results = {};

    for (const [metric, threshold] of Object.entries(this.thresholds.global)) {
      const actual = Math.round((coverage[metric].covered / coverage[metric].total) * 100);
      const meetsThreshold = actual >= threshold;

      results[metric] = { actual, threshold, meetsThreshold };

      const status = meetsThreshold ? '✅ PASS' : '❌ FAIL';
      const diff = actual - threshold;
      const diffStr = diff >= 0 ? `+${diff}%` : `${diff}%`;

      console.log(`   ${metric}: ${actual}% (target: ${threshold}%) ${status} (${diffStr})`);

      if (!meetsThreshold) {
        allThresholdsMet = false;
      }
    }

    if (!allThresholdsMet) {
      console.log('');
      console.log('❌ Coverage thresholds not met:');

      for (const [metric, result] of Object.entries(results)) {
        if (!result.meetsThreshold) {
          const deficit = result.threshold - result.actual;
          console.log(
            `   ${metric}: Need ${deficit}% more coverage (${result.actual}% → ${result.threshold}%)`
          );
        }
      }

      throw new Error('Coverage thresholds not met');
    }

    this.coverageResults = results;
    return results;
  }

  async generatePreCommitReport() {
    console.log('📄 Generating pre-commit coverage report...');

    const report = {
      timestamp: new Date().toISOString(),
      commit: this.getCurrentCommit(),
      branch: this.getCurrentBranch(),
      stagedFiles: this.stagedFiles || [],
      coverage: this.coverageResults,
      thresholds: this.thresholds,
      status: 'PASSED',
      summary: {
        overallScore: 100,
        metricsMet: Object.values(this.coverageResults).filter((r) => r.meetsThreshold).length,
        totalMetrics: Object.keys(this.coverageResults).length,
      },
    };

    // Save pre-commit report
    const reportDir = path.join(this.projectRoot, 'artifacts', 'coverage', 'pre-commit');
    await fs.mkdir(reportDir, { recursive: true });

    const reportPath = path.join(reportDir, `pre-commit-${Date.now()}.json`);
    await fs.writeFile(reportPath, JSON.stringify(report, null, 2));

    console.log('📋 Pre-commit report saved to:', reportPath);
  }

  async checkCoverageRegression() {
    console.log('📉 Checking for coverage regression...');

    try {
      const previousReportPath = path.join(
        this.projectRoot,
        'artifacts',
        'coverage',
        'pre-commit',
        'latest.json'
      );

      if (await this.fileExists(previousReportPath)) {
        const previousReport = JSON.parse(await fs.readFile(previousReportPath, 'utf8'));

        let hasRegression = false;

        for (const [metric, currentResult] of Object.entries(this.coverageResults)) {
          const previousResult = previousReport.coverage?.[metric];

          if (previousResult) {
            const regression = currentResult.actual - previousResult.actual;

            if (regression < -5) {
              // 5% regression threshold
              console.log(
                `⚠️  ${metric} coverage regression detected: ${previousResult.actual}% → ${currentResult.actual}% (${regression}%)`
              );
              hasRegression = true;
            }
          }
        }

        if (hasRegression) {
          console.log('❌ Significant coverage regression detected');
          throw new Error('Coverage regression detected');
        } else {
          console.log('✅ No significant coverage regression detected');
        }
      } else {
        console.log('ℹ️  No previous coverage report found for regression check');
      }
    } catch (error) {
      if (error.message !== 'Coverage regression detected') {
        console.warn('⚠️  Could not check for regression:', error.message);
      } else {
        throw error;
      }
    }
  }

  async validateCriticalFiles() {
    console.log('🔍 Validating critical file coverage...');

    const criticalFiles = [
      'src/index.ts',
      'src/services/memory-store.ts',
      'src/db/adapters/qdrant-adapter.ts',
      'src/services/orchestrators/memory-find-orchestrator.ts',
      'src/services/orchestrators/memory-store-orchestrator.ts',
    ];

    const coverageFilePath = path.join(this.coverageDir, 'comprehensive', 'coverage.json');

    if (!(await this.fileExists(coverageFilePath))) {
      console.log('⚠️  Detailed coverage file not found, skipping critical file validation');
      return;
    }

    const coverageData = JSON.parse(await fs.readFile(coverageFilePath, 'utf8'));

    for (const criticalFile of criticalFiles) {
      const absolutePath = path.resolve(this.projectRoot, criticalFile);
      const fileCoverage = coverageData[absolutePath];

      if (fileCoverage) {
        const coverage = this.calculateFileCoverage(fileCoverage);
        const avgCoverage = this.calculateAverageCoverage(coverage);

        if (avgCoverage < 85) {
          console.log(`⚠️  Critical file ${criticalFile} has low coverage: ${avgCoverage}%`);
        } else {
          console.log(`✅ Critical file ${criticalFile} coverage: ${avgCoverage}%`);
        }
      }
    }
  }

  getCurrentCommit() {
    try {
      return execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim();
    } catch {
      return 'unknown';
    }
  }

  getCurrentBranch() {
    try {
      return execSync('git rev-parse --abbrev-ref HEAD', { encoding: 'utf8' }).trim();
    } catch {
      return 'unknown';
    }
  }

  calculateFileCoverage(fileData) {
    return {
      lines: { total: fileData.l?.total || 0, covered: fileData.l?.covered || 0 },
      functions: { total: fileData.f?.total || 0, covered: fileData.f?.covered || 0 },
      branches: { total: fileData.b?.total || 0, covered: fileData.b?.covered || 0 },
      statements: { total: fileData.s?.total || 0, covered: fileData.s?.covered || 0 },
    };
  }

  calculateAverageCoverage(coverage) {
    const metrics = ['lines', 'functions', 'branches', 'statements'];
    const total = metrics.reduce((sum, metric) => {
      const data = coverage[metric];
      if (!data || data.total === 0) return sum;
      return sum + (data.covered / data.total) * 100;
    }, 0);
    return Math.round(total / metrics.length);
  }

  async fileExists(filePath) {
    try {
      await fs.access(filePath);
      return true;
    } catch {
      return false;
    }
  }
}

// Run the pre-commit validation
if (import.meta.url === `file://${process.argv[1]}`) {
  const validator = new PreCommitCoverageValidator();
  validator
    .init()
    .then((success) => {
      process.exit(success ? 0 : 1);
    })
    .catch((error) => {
      console.error('Validation error:', error.message);
      process.exit(1);
    });
}

export default PreCommitCoverageValidator;
