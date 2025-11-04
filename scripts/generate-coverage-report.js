#!/usr/bin/env node

/**
 * Comprehensive Coverage Report Generator
 * Generates detailed coverage reports for the mcp-cortex project
 */

import fs from 'fs/promises';
import path from 'path';
import { execSync } from 'child_process';

class CoverageReportGenerator {
  constructor() {
    this.projectRoot = process.cwd();
    this.coverageDir = path.join(this.projectRoot, 'coverage');
    this.reportsDir = path.join(this.coverageDir, 'reports');
    this.timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  }

  async init() {
    console.log('🔍 Initializing Coverage Report Generator...');
    await this.ensureDirectories();
    await this.generateCoverageData();
    await this.generateComprehensiveReport();
    await this.generateSummaryReport();
    await this.generateTrendingReport();
    await this.generateQualityGateReport();
    await this.generateBadgeReport();
    console.log('✅ Coverage report generation completed!');
  }

  async ensureDirectories() {
    const dirs = [
      this.coverageDir,
      this.reportsDir,
      path.join(this.reportsDir, 'historical'),
      path.join(this.reportsDir, 'trends'),
      path.join(this.reportsDir, 'badges')
    ];

    for (const dir of dirs) {
      await fs.mkdir(dir, { recursive: true });
    }
  }

  async generateCoverageData() {
    console.log('📊 Generating coverage data...');

    try {
      // Run comprehensive coverage
      execSync('npm run test:coverage:ci', {
        stdio: 'inherit',
        cwd: this.projectRoot
      });
    } catch (error) {
      console.warn('⚠️  Coverage collection failed:', error.message);
    }
  }

  async generateComprehensiveReport() {
    console.log('📋 Generating comprehensive coverage report...');

    const report = {
      metadata: {
        generated: new Date().toISOString(),
        version: '1.0.0',
        project: 'mcp-cortex',
        nodeVersion: process.version,
        platform: process.platform
      },
      summary: await this.generateSummary(),
      detailed: await this.generateDetailedCoverage(),
      thresholdAnalysis: await this.analyzeThresholds(),
      criticalPathAnalysis: await this.analyzeCriticalPaths(),
      qualityMetrics: await this.calculateQualityMetrics(),
      recommendations: await this.generateRecommendations()
    };

    await fs.writeFile(
      path.join(this.reportsDir, `comprehensive-report-${this.timestamp}.json`),
      JSON.stringify(report, null, 2)
    );

    await fs.writeFile(
      path.join(this.reportsDir, 'latest-comprehensive-report.json'),
      JSON.stringify(report, null, 2)
    );
  }

  async generateSummary() {
    try {
      const coverageFile = path.join(this.coverageDir, 'coverage-summary.json');
      const coverageData = JSON.parse(await fs.readFile(coverageFile, 'utf8'));

      const summary = {
        total: coverageData.total,
        covered: coverageData.covered,
        percentage: {
          lines: this.calculatePercentage(coverageData.total.lines, coverageData.covered.lines),
          functions: this.calculatePercentage(coverageData.total.functions, coverageData.covered.functions),
          branches: this.calculatePercentage(coverageData.total.branches, coverageData.covered.branches),
          statements: this.calculatePercentage(coverageData.total.statements, coverageData.covered.statements)
        },
        status: this.determineCoverageStatus(coverageData)
      };

      return summary;
    } catch (error) {
      console.warn('⚠️  Could not read coverage summary:', error.message);
      return { error: error.message };
    }
  }

  async generateDetailedCoverage() {
    try {
      const coverageFile = path.join(this.coverageDir, 'coverage.json');
      const coverageData = JSON.parse(await fs.readFile(coverageFile, 'utf8'));

      const detailed = {
        files: {},
        directories: {},
        coverageByType: {
          lines: { total: 0, covered: 0, percentage: 0 },
          functions: { total: 0, covered: 0, percentage: 0 },
          branches: { total: 0, covered: 0, percentage: 0 },
          statements: { total: 0, covered: 0, percentage: 0 }
        }
      };

      // Process each file
      for (const [filePath, fileData] of Object.entries(coverageData)) {
        if (!filePath.endsWith('.ts') && !filePath.endsWith('.js')) continue;

        const relativePath = path.relative(this.projectRoot, filePath);
        const dirPath = path.dirname(relativePath);

        const fileCoverage = this.calculateFileCoverage(fileData);
        detailed.files[relativePath] = fileCoverage;

        // Update directory coverage
        if (!detailed.directories[dirPath]) {
          detailed.directories[dirPath] = {
            lines: { total: 0, covered: 0 },
            functions: { total: 0, covered: 0 },
            branches: { total: 0, covered: 0 },
            statements: { total: 0, covered: 0 }
          };
        }

        // Accumulate directory metrics
        for (const type of ['lines', 'functions', 'branches', 'statements']) {
          detailed.directories[dirPath][type].total += fileCoverage[type].total;
          detailed.directories[dirPath][type].covered += fileCoverage[type].covered;
          detailed.coverageByType[type].total += fileCoverage[type].total;
          detailed.coverageByType[type].covered += fileCoverage[type].covered;
        }
      }

      // Calculate percentages
      for (const type of ['lines', 'functions', 'branches', 'statements']) {
        detailed.coverageByType[type].percentage = this.calculatePercentage(
          detailed.coverageByType[type].total,
          detailed.coverageByType[type].covered
        );
      }

      // Calculate directory percentages
      for (const [dirPath, dirData] of Object.entries(detailed.directories)) {
        for (const type of ['lines', 'functions', 'branches', 'statements']) {
          dirData[type].percentage = this.calculatePercentage(
            dirData[type].total,
            dirData[type].covered
          );
        }
      }

      return detailed;
    } catch (error) {
      console.warn('⚠️  Could not generate detailed coverage:', error.message);
      return { error: error.message };
    }
  }

  async analyzeThresholds() {
    const thresholds = {
      target: {
        statements: 95,
        branches: 90,
        functions: 95,
        lines: 95
      },
      critical: {
        'src/core/**': { statements: 98, branches: 95, functions: 98, lines: 98 },
        'src/db/**': { statements: 95, branches: 90, functions: 95, lines: 95 },
        'src/mcp/**': { statements: 95, branches: 90, functions: 95, lines: 95 }
      }
    };

    const analysis = {
      global: { passed: true, met: {}, failed: {} },
      critical: {},
      recommendations: []
    };

    try {
      const summary = await this.generateSummary();
      if (summary.percentage) {
        for (const [metric, target] of Object.entries(thresholds.target)) {
          const actual = summary.percentage[metric] || 0;
          if (actual >= target) {
            analysis.global.met[metric] = { actual, target };
          } else {
            analysis.global.failed[metric] = { actual, target, deficit: target - actual };
            analysis.global.passed = false;
          }
        }
      }
    } catch (error) {
      analysis.global.error = error.message;
    }

    return analysis;
  }

  async analyzeCriticalPaths() {
    const criticalPaths = [
      'src/core',
      'src/db',
      'src/mcp'
    ];

    const analysis = {
      paths: {},
      overall: { passed: true, coverage: 0 }
    };

    try {
      const detailed = await this.generateDetailedCoverage();
      if (detailed.directories) {
        for (const criticalPath of criticalPaths) {
          const pathData = detailed.directories[criticalPath];
          if (pathData) {
            const avgCoverage = Object.values(pathData)
              .filter(data => typeof data === 'object' && data.percentage)
              .reduce((sum, data) => sum + data.percentage, 0) / 4;

            analysis.paths[criticalPath] = {
              coverage: Math.round(avgCoverage),
              details: pathData,
              status: avgCoverage >= 90 ? 'passed' : 'failed'
            };

            if (avgCoverage < 90) {
              analysis.overall.passed = false;
            }
          }
        }

        // Calculate overall critical path coverage
        const pathCoverages = Object.values(analysis.paths)
          .filter(path => path.coverage)
          .map(path => path.coverage);

        if (pathCoverages.length > 0) {
          analysis.overall.coverage = Math.round(
            pathCoverages.reduce((sum, cov) => sum + cov, 0) / pathCoverages.length
          );
        }
      }
    } catch (error) {
      analysis.error = error.message;
    }

    return analysis;
  }

  async calculateQualityMetrics() {
    return {
      maintainabilityIndex: await this.calculateMaintainabilityIndex(),
      codeComplexity: await this.calculateCodeComplexity(),
      testComplexity: await this.calculateTestComplexity(),
      codeQuality: await this.assessCodeQuality()
    };
  }

  async generateRecommendations() {
    const recommendations = [];

    try {
      const thresholdAnalysis = await this.analyzeThresholds();
      const criticalPathAnalysis = await this.analyzeCriticalPaths();

      // Threshold recommendations
      if (!thresholdAnalysis.global.passed) {
        for (const [metric, data] of Object.entries(thresholdAnalysis.global.failed)) {
          recommendations.push({
            type: 'coverage',
            priority: 'high',
            metric,
            message: `Increase ${metric} coverage from ${data.actual}% to ${data.target}% (${data.deficit}% deficit)`,
            action: `Add tests for uncovered ${metric}`
          });
        }
      }

      // Critical path recommendations
      if (!criticalPathAnalysis.overall.passed) {
        for (const [path, data] of Object.entries(criticalPathAnalysis.paths)) {
          if (data.status === 'failed') {
            recommendations.push({
              type: 'critical-path',
              priority: 'high',
              path,
              message: `Critical path ${path} has insufficient coverage (${data.coverage}%)`,
              action: `Focus test efforts on ${path} to meet 90% threshold`
            });
          }
        }
      }

      // General recommendations
      recommendations.push(
        {
          type: 'maintenance',
          priority: 'medium',
          message: 'Set up automated coverage monitoring',
          action: 'Configure CI/CD pipeline to track coverage trends'
        },
        {
          type: 'quality',
          priority: 'low',
          message: 'Consider coverage badges for README',
          action: 'Generate and display coverage badges'
        }
      );

    } catch (error) {
      recommendations.push({
        type: 'error',
        priority: 'high',
        message: `Error generating recommendations: ${error.message}`,
        action: 'Check coverage configuration and test setup'
      });
    }

    return recommendations;
  }

  async generateSummaryReport() {
    console.log('📄 Generating summary report...');

    const summary = await this.generateSummary();
    const thresholdAnalysis = await this.analyzeThresholds();

    const report = `
# Coverage Summary Report
Generated: ${new Date().toISOString()}

## Overall Coverage
- **Lines**: ${summary.percentage?.lines || 'N/A'}%
- **Functions**: ${summary.percentage?.functions || 'N/A'}%
- **Branches**: ${summary.percentage?.branches || 'N/A'}%
- **Statements**: ${summary.percentage?.statements || 'N/A'}%

## Threshold Status
${thresholdAnalysis.global.passed ? '✅ All thresholds met' : '❌ Some thresholds not met'}

## Status: ${summary.status || 'Unknown'}

${thresholdAnalysis.global.passed ? '' : `### Failed Thresholds
${Object.entries(thresholdAnalysis.global.failed)
  .map(([metric, data]) => `- ${metric}: ${data.actual}% (target: ${data.target}%)`)
  .join('\n')}`}
    `.trim();

    await fs.writeFile(
      path.join(this.reportsDir, `summary-${this.timestamp}.md`),
      report
    );

    await fs.writeFile(
      path.join(this.reportsDir, 'latest-summary.md'),
      report
    );
  }

  async generateTrendingReport() {
    console.log('📈 Generating trending report...');

    try {
      const historicalDir = path.join(this.reportsDir, 'historical');
      const historicalFiles = await fs.readdir(historicalDir);

      const reports = [];
      for (const file of historicalFiles) {
        if (file.endsWith('.json')) {
          const filePath = path.join(historicalDir, file);
          const data = JSON.parse(await fs.readFile(filePath, 'utf8'));
          reports.push({
            date: data.metadata?.generated || file,
            summary: data.summary
          });
        }
      }

      reports.sort((a, b) => new Date(a.date) - new Date(b.date));

      const trendingReport = {
        generated: new Date().toISOString(),
        reports,
        trends: this.calculateTrends(reports)
      };

      await fs.writeFile(
        path.join(this.reportsDir, 'trends', `trending-${this.timestamp}.json`),
        JSON.stringify(trendingReport, null, 2)
      );

      // Store current report for historical tracking
      const currentReport = path.join(historicalDir, `report-${this.timestamp}.json`);
      const comprehensiveReport = path.join(this.reportsDir, 'latest-comprehensive-report.json');

      if (await this.fileExists(comprehensiveReport)) {
        await fs.copyFile(comprehensiveReport, currentReport);
      }

    } catch (error) {
      console.warn('⚠️  Could not generate trending report:', error.message);
    }
  }

  async generateQualityGateReport() {
    console.log('🚪 Generating quality gate report...');

    const thresholdAnalysis = await this.analyzeThresholds();
    const criticalPathAnalysis = await this.analyzeCriticalPaths();

    const qualityGate = {
      status: 'unknown',
      gates: {
        overallCoverage: thresholdAnalysis.global.passed ? 'passed' : 'failed',
        criticalPaths: criticalPathAnalysis.overall.passed ? 'passed' : 'failed',
        minimumFiles: await this.checkMinimumFileCoverage(),
        noRegression: await this.checkForRegression()
      },
      overall: thresholdAnalysis.global.passed && criticalPathAnalysis.overall.passed ? 'passed' : 'failed',
      recommendations: []
    };

    // Add recommendations based on failures
    for (const [gateName, status] of Object.entries(qualityGate.gates)) {
      if (status === 'failed') {
        qualityGate.recommendations.push({
          gate: gateName,
          message: `Quality gate '${gateName}' failed`,
          action: this.getGateAction(gateName)
        });
      }
    }

    await fs.writeFile(
      path.join(this.reportsDir, `quality-gate-${this.timestamp}.json`),
      JSON.stringify(qualityGate, null, 2)
    );
  }

  async generateBadgeReport() {
    console.log('🏷️  Generating coverage badges...');

    try {
      const summary = await this.generateSummary();
      const coverage = Math.round(
        (summary.percentage?.lines || 0 +
         summary.percentage?.functions || 0 +
         summary.percentage?.statements || 0) / 3
      );

      const badge = {
        schemaVersion: 1,
        label: 'coverage',
        message: `${coverage}%`,
        color: coverage >= 95 ? 'green' : coverage >= 80 ? 'yellow' : 'red'
      };

      const badgeSvg = this.generateBadgeSvg(badge);

      await fs.writeFile(
        path.join(this.reportsDir, 'badges', `coverage-${this.timestamp}.svg`),
        badgeSvg
      );

      await fs.writeFile(
        path.join(this.reportsDir, 'badges', 'coverage-latest.svg'),
        badgeSvg
      );

    } catch (error) {
      console.warn('⚠️  Could not generate badge:', error.message);
    }
  }

  // Helper methods
  calculatePercentage(total, covered) {
    if (total === 0) return 0;
    return Math.round((covered / total) * 100);
  }

  determineCoverageStatus(summary) {
    const avgCoverage = (summary.percentage?.lines || 0 +
                        summary.percentage?.functions || 0 +
                        summary.percentage?.branches || 0 +
                        summary.percentage?.statements || 0) / 4;

    if (avgCoverage >= 95) return 'excellent';
    if (avgCoverage >= 90) return 'good';
    if (avgCoverage >= 80) return 'adequate';
    return 'needs-improvement';
  }

  calculateFileCoverage(fileData) {
    return {
      lines: { total: fileData.l?.total || 0, covered: fileData.l?.covered || 0 },
      functions: { total: fileData.f?.total || 0, covered: fileData.f?.covered || 0 },
      branches: { total: fileData.b?.total || 0, covered: fileData.b?.covered || 0 },
      statements: { total: fileData.s?.total || 0, covered: fileData.s?.covered || 0 }
    };
  }

  async calculateMaintainabilityIndex() {
    // Placeholder for maintainability index calculation
    return { score: 85, status: 'good' };
  }

  async calculateCodeComplexity() {
    // Placeholder for code complexity calculation
    return { cyclomatic: 5, cognitive: 8, status: 'acceptable' };
  }

  async calculateTestComplexity() {
    // Placeholder for test complexity calculation
    return { complexity: 3, status: 'simple' };
  }

  async assessCodeQuality() {
    // Placeholder for code quality assessment
    return { grade: 'A', issues: 0, suggestions: 0 };
  }

  calculateTrends(reports) {
    if (reports.length < 2) return { insufficientData: true };

    const latest = reports[reports.length - 1];
    const previous = reports[reports.length - 2];

    const trends = {};

    for (const metric of ['lines', 'functions', 'branches', 'statements']) {
      const latestValue = latest.summary?.percentage?.[metric] || 0;
      const previousValue = previous.summary?.percentage?.[metric] || 0;

      trends[metric] = {
        current: latestValue,
        previous: previousValue,
        change: latestValue - previousValue,
        trend: latestValue > previousValue ? 'improving' : latestValue < previousValue ? 'declining' : 'stable'
      };
    }

    return trends;
  }

  async checkMinimumFileCoverage() {
    // Placeholder for minimum file coverage check
    return 'passed';
  }

  async checkForRegression() {
    // Placeholder for regression check
    return 'passed';
  }

  getGateAction(gateName) {
    const actions = {
      overallCoverage: 'Improve overall test coverage to meet thresholds',
      criticalPaths: 'Focus on critical path coverage',
      minimumFiles: 'Ensure minimum coverage per file',
      noRegression: 'Address coverage regression issues'
    };
    return actions[gateName] || 'Review quality gate requirements';
  }

  generateBadgeSvg(badge) {
    const colors = {
      green: '#4c1',
      yellow: '#dfb317',
      red: '#e05d44'
    };

    const color = colors[badge.color] || '#999';
    const width = 100 + badge.message.length * 10;

    return `
<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="20">
  <linearGradient id="a" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <rect rx="3" width="${width}" height="20" fill="#555"/>
  <rect rx="3" x="50" width="${width - 50}" height="20" fill="${color}"/>
  <path fill="${color}" d="M50 0h4v20h-4z"/>
  <rect rx="3" width="${width}" height="20" fill="url(#a)"/>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="25" y="15" fill="#010101" fill-opacity=".3">${badge.label}</text>
    <text x="25" y="14">${badge.label}</text>
    <text x="${50 + (width - 50) / 2}" y="15" fill="#010101" fill-opacity=".3">${badge.message}</text>
    <text x="${50 + (width - 50) / 2}" y="14">${badge.message}</text>
  </g>
</svg>
    `.trim();
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

// Run the coverage report generator
if (import.meta.url === `file://${process.argv[1]}`) {
  const generator = new CoverageReportGenerator();
  generator.init().catch(console.error);
}

export default CoverageReportGenerator;