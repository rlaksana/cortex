// ULTIMATE FINAL EMERGENCY ROLLBACK: Remaining systematic type issues

/**
 * CI Performance Regression Guard
 *
 * Automated performance regression detection and enforcement for CI pipelines
 * with configurable thresholds, automated reporting, and failure handling
 */

import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { randomUUID } from 'crypto';

import type { PerformanceRegression,PerformanceTestResult } from './performance-harness.js';
import type { PerformanceTestConfig } from './performance-targets.js';

export interface RegressionGuardConfig {
  /** Base directory for baseline storage */
  baselineDir: string;
  /** Directory for regression reports */
  reportsDir: string;
  /** Maximum regression percentage before failure */
  maxRegressionPercentage: number;
  /** Minimum number of baseline samples required */
  minBaselineSamples: number;
  /** Critical metrics that must not regress */
  criticalMetrics: string[];
  /** Warning metrics that can regress with warnings */
  warningMetrics: string[];
  /** Enable trend analysis */
  enableTrendAnalysis: boolean;
  /** Trend window size (number of recent results) */
  trendWindowSize: number;
  /** Auto-update baseline on improvements */
  autoUpdateBaseline: boolean;
  /** Performance gate enabled */
  performanceGateEnabled: boolean;
  /** Slack notifications configuration */
  notifications?: {
    slack?: {
      webhookUrl: string;
      channel: string;
    };
    email?: {
      smtp: {
        host: string;
        port: number;
        secure: boolean;
      };
      from: string;
      to: string[];
    };
  };
}

export interface BaselineEntry {
  /** Test configuration */
  config: PerformanceTestConfig;
  /** Performance metrics */
  metrics: {
    latencies: { p50: number; p95: number; p99: number; min: number; max: number };
    throughput: number;
    errorRate: number;
    memoryUsage: { peak: number; average: number };
  };
  /** Summary statistics */
  summary: {
    totalOperations: number;
    totalDuration: number;
    errors: number;
    successRate: number;
    throughput: number;
  };
  /** Timestamp */
  timestamp: string;
  /** Test ID */
  testId: string;
  /** Environment info */
  environment: {
    nodeVersion: string;
    platform: string;
    arch: string;
  };
}

export interface RegressionReport {
  /** Report ID */
  reportId: string;
  /** Test name */
  testName: string;
  /** Timestamp */
  timestamp: string;
  /** Regression detected */
  regressionDetected: boolean;
  /** Regression details */
  regressions: Array<{
    metric: string;
    baseline: number;
    current: number;
    change: number;
    changePercentage: number;
    severity: 'critical' | 'major' | 'minor';
    target: number;
  }>;
  /** Improvements */
  improvements: Array<{
    metric: string;
    baseline: number;
    current: number;
    change: number;
    changePercentage: number;
  }>;
  /** Overall assessment */
  assessment: {
    status: 'pass' | 'warning' | 'fail';
    summary: string;
    recommendations: string[];
  };
  /** CI gate status */
  ciGateStatus: {
    passed: boolean;
    reason?: string;
    canProceed: boolean;
  };
}

export interface TrendAnalysis {
  /** Trend direction */
  direction: 'improving' | 'degrading' | 'stable';
  /** Trend strength */
  strength: number; // 0-1
  /** Prediction for next run */
  prediction: number;
  /** Confidence level */
  confidence: number; // 0-1
}

export class CIRegressionGuard {
  private config: RegressionGuardConfig;
  private baselineCache: Map<string, BaselineEntry[]> = new Map();

  constructor(config?: Partial<RegressionGuardConfig>) {
    this.config = {
      baselineDir: './artifacts/performance/baseline',
      reportsDir: './artifacts/performance/regression-reports',
      maxRegressionPercentage: 20,
      minBaselineSamples: 3,
      criticalMetrics: ['p95_latency', 'p99_latency', 'throughput', 'error_rate'],
      warningMetrics: ['p50_latency', 'memory_usage'],
      enableTrendAnalysis: true,
      trendWindowSize: 10,
      autoUpdateBaseline: true,
      performanceGateEnabled: true,
      ...config,
    };

    this.ensureDirectories();
    this.loadBaselines();
  }

  /**
   * Check for performance regressions in test results
   */
  async checkRegressions(results: PerformanceTestResult[]): Promise<RegressionReport[]> {
    const reports: RegressionReport[] = [];

    for (const result of results) {
      const report = await this.analyzeResult(result);
      reports.push(report);
    }

    // Generate summary report
    await this.generateSummaryReport(reports);

    // Send notifications if configured
    if (this.config.notifications) {
      await this.sendNotifications(reports);
    }

    return reports;
  }

  /**
   * Analyze individual test result for regressions
   */
  private async analyzeResult(result: PerformanceTestResult): Promise<RegressionReport> {
    const baseline = this.getBaseline(result.config.name);

    if (!baseline) {
      console.log(`⚠️  No baseline found for test: ${result.config.name}`);
      return this.createNoBaselineReport(result);
    }

    const regressions = this.detectRegressions(result, baseline);
    const improvements = this.detectImprovements(result, baseline);

    // Convert to PerformanceRegression format for assessment
    const regressionAnalysis: PerformanceRegression[] = regressions.map(reg => ({
      testName: result.config.name,
      detected: true,
      details: [{
        metric: reg.metric,
        baseline: reg.baseline,
        current: reg.current,
        change: reg.change,
        changePercentage: reg.changePercentage,
        significance: reg.severity === 'critical' ? 'major' : reg.severity === 'major' ? 'major' : 'minor'
      }],
      impact: {
        severity: reg.severity === 'critical' ? 'critical' : reg.severity === 'major' ? 'high' : 'medium',
        affectedOperations: [reg.metric],
        recommendations: [`Investigate ${reg.metric} regression`]
      }
    }));

    const improvementAnalysis: PerformanceRegression[] = improvements.map(imp => ({
      testName: result.config.name,
      detected: false,
      details: [{
        metric: imp.metric,
        baseline: imp.baseline,
        current: imp.current,
        change: imp.change,
        changePercentage: imp.changePercentage,
        significance: 'minor'
      }],
      impact: {
        severity: 'low',
        affectedOperations: [imp.metric],
        recommendations: []
      }
    }));

    const assessment = this.assessPerformance(regressionAnalysis, improvementAnalysis);
    const ciGateStatus = this.evaluateCIGate(assessment, regressions);

    const report: RegressionReport = {
      reportId: randomUUID(),
      testName: result.config.name,
      timestamp: new Date().toISOString(),
      regressionDetected: regressions.length > 0,
      regressions,
      improvements,
      assessment,
      ciGateStatus,
    };

    // Store regression report
    await this.storeRegressionReport(report);

    // Auto-update baseline if there are significant improvements
    if (this.config.autoUpdateBaseline && improvements.length > 0) {
      const hasSignificantImprovement = improvements.some(
        (imp) => Math.abs(imp.changePercentage) > 10
      );
      if (hasSignificantImprovement) {
        await this.updateBaseline(result);
      }
    }

    return report;
  }

  /**
   * Detect performance regressions
   */
  private detectRegressions(
    result: PerformanceTestResult,
    baseline: BaselineEntry
  ): Array<{
    metric: string;
    baseline: number;
    current: number;
    change: number;
    changePercentage: number;
    severity: 'critical' | 'major' | 'minor';
    target: number;
  }> {
    const regressions = [];
    const currentMetrics = result.results.metrics;
    const baselineMetrics = baseline.metrics;

    const metricDefinitions = [
      {
        name: 'p50_latency',
        current: currentMetrics.latencies.p50,
        baseline: baselineMetrics.latencies.p50,
        target: 500,
        higherIsWorse: true,
      },
      {
        name: 'p95_latency',
        current: currentMetrics.latencies.p95,
        baseline: baselineMetrics.latencies.p95,
        target: 1000,
        higherIsWorse: true,
      },
      {
        name: 'p99_latency',
        current: currentMetrics.latencies.p99,
        baseline: baselineMetrics.latencies.p99,
        target: 2000,
        higherIsWorse: true,
      },
      {
        name: 'throughput',
        current: currentMetrics.throughput,
        baseline: baselineMetrics.throughput,
        target: 100,
        higherIsWorse: false,
      },
      {
        name: 'error_rate',
        current: currentMetrics.errorRate,
        baseline: baselineMetrics.errorRate,
        target: 1,
        higherIsWorse: true,
      },
      {
        name: 'memory_usage',
        current: currentMetrics.memoryUsage.peak,
        baseline: baselineMetrics.memoryUsage.peak,
        target: 512 * 1024 * 1024,
        higherIsWorse: true,
      },
    ];

    for (const metric of metricDefinitions) {
      const change = metric.current - metric.baseline;
      const changePercentage = (change / metric.baseline) * 100;

      // Check if this is a regression
      const isRegression = metric.higherIsWorse ? change > 0 : change < 0;
      const exceedsThreshold = Math.abs(changePercentage) > this.config.maxRegressionPercentage;

      if (isRegression && exceedsThreshold) {
        let severity: 'critical' | 'major' | 'minor';

        // Determine severity based on metric type and regression amount
        if (this.config.criticalMetrics.includes(metric.name)) {
          severity = Math.abs(changePercentage) > 50 ? 'critical' : 'major';
        } else {
          severity = Math.abs(changePercentage) > 30 ? 'major' : 'minor';
        }

        regressions.push({
          metric: metric.name,
          baseline: metric.baseline,
          current: metric.current,
          change,
          changePercentage,
          severity,
          target: metric.target,
        });
      }
    }

    return regressions;
  }

  /**
   * Detect performance improvements
   */
  private detectImprovements(
    result: PerformanceTestResult,
    baseline: BaselineEntry
  ): Array<{
    metric: string;
    baseline: number;
    current: number;
    change: number;
    changePercentage: number;
  }> {
    const improvements = [];
    const currentMetrics = result.results.metrics;
    const baselineMetrics = baseline.metrics;

    const metricDefinitions = [
      {
        name: 'p50_latency',
        current: currentMetrics.latencies.p50,
        baseline: baselineMetrics.latencies.p50,
        higherIsWorse: true,
      },
      {
        name: 'p95_latency',
        current: currentMetrics.latencies.p95,
        baseline: baselineMetrics.latencies.p95,
        higherIsWorse: true,
      },
      {
        name: 'p99_latency',
        current: currentMetrics.latencies.p99,
        baseline: baselineMetrics.latencies.p99,
        higherIsWorse: true,
      },
      {
        name: 'throughput',
        current: currentMetrics.throughput,
        baseline: baselineMetrics.throughput,
        higherIsWorse: false,
      },
      {
        name: 'error_rate',
        current: currentMetrics.errorRate,
        baseline: baselineMetrics.errorRate,
        higherIsWorse: true,
      },
      {
        name: 'memory_usage',
        current: currentMetrics.memoryUsage.peak,
        baseline: baselineMetrics.memoryUsage.peak,
        higherIsWorse: true,
      },
    ];

    for (const metric of metricDefinitions) {
      const change = metric.current - metric.baseline;
      const changePercentage = (change / metric.baseline) * 100;

      // Check if this is an improvement
      const isImprovement = metric.higherIsWorse ? change < 0 : change > 0;
      const significantImprovement = Math.abs(changePercentage) > 5; // 5% improvement threshold

      if (isImprovement && significantImprovement) {
        improvements.push({
          metric: metric.name,
          baseline: metric.baseline,
          current: metric.current,
          change,
          changePercentage,
        });
      }
    }

    return improvements;
  }

  /**
   * Assess overall performance
   */
  private assessPerformance(
    regressions: PerformanceRegression[],
    improvements: PerformanceRegression[]
  ): {
    status: 'pass' | 'warning' | 'fail';
    summary: string;
    recommendations: string[];
  } {
    const criticalRegressions = regressions.filter((r) => r.impact.severity === 'critical');
    const majorRegressions = regressions.filter((r) => r.impact.severity === 'high');
    const minorRegressions = regressions.filter((r) => r.impact.severity === 'medium');

    let status: 'pass' | 'warning' | 'fail';
    let summary: string;
    const recommendations: string[] = [];

    if (criticalRegressions.length > 0) {
      status = 'fail';
      summary = `❌ CRITICAL PERFORMANCE REGRESSIONS DETECTED: ${criticalRegressions.length} critical, ${majorRegressions.length} major, ${minorRegressions.length} minor`;
      recommendations.push(
        '🚨 BLOCK DEPLOYMENT - Critical performance regressions must be resolved'
      );
      recommendations.push('Investigate and fix critical regressions before proceeding');
    } else if (majorRegressions.length > 0) {
      status = 'warning';
      summary = `⚠️ PERFORMANCE REGRESSIONS DETECTED: ${majorRegressions.length} major, ${minorRegressions.length} minor`;
      recommendations.push('Review major regressions and consider fixing before deployment');
      recommendations.push('Monitor performance in production if proceeding');
    } else if (minorRegressions.length > 0) {
      status = 'warning';
      summary = `⚠️ MINOR PERFORMANCE REGRESSIONS: ${minorRegressions.length} minor regressions detected`;
      recommendations.push('Monitor minor regressions in production');
    } else if (improvements.length > 0) {
      status = 'pass';
      summary = `✅ PERFORMANCE IMPROVEMENTS: ${improvements.length} improvements detected, no regressions`;
      recommendations.push('Performance improvements detected - consider updating baseline');
    } else {
      status = 'pass';
      summary = '✅ PERFORMANCE STABLE: No significant changes detected';
      recommendations.push('Performance is stable - ready for deployment');
    }

    return { status, summary, recommendations };
  }

  /**
   * Evaluate CI gate status
   */
  private evaluateCIGate(
    assessment: {
      status: 'pass' | 'warning' | 'fail';
      summary: string;
      recommendations: string[];
    },
    regressions: Array<{
      metric: string;
      baseline: number;
      current: number;
      change: number;
      changePercentage: number;
      severity: 'critical' | 'major' | 'minor';
      target: number;
    }>
  ): {
    passed: boolean;
    reason?: string;
    canProceed: boolean;
  } {
    if (!this.config.performanceGateEnabled) {
      return {
        passed: true,
        reason: 'Performance gate disabled',
        canProceed: true,
      };
    }

    const criticalRegressions = regressions.filter((r) => r.severity === 'critical');
    const majorRegressions = regressions.filter((r) => r.severity === 'major');

    if (criticalRegressions.length > 0) {
      return {
        passed: false,
        reason: `Critical performance regressions detected: ${criticalRegressions.length}`,
        canProceed: false,
      };
    }

    if (majorRegressions.length > 0) {
      return {
        passed: false,
        reason: `Major performance regressions detected: ${majorRegressions.length}`,
        canProceed: false,
      };
    }

    if (assessment.status === 'fail') {
      return {
        passed: false,
        reason: assessment.summary,
        canProceed: false,
      };
    }

    return {
      passed: true,
      canProceed: true,
    };
  }

  /**
   * Create report for tests without baseline
   */
  private createNoBaselineReport(result: PerformanceTestResult): RegressionReport {
    return {
      reportId: randomUUID(),
      testName: result.config.name,
      timestamp: new Date().toISOString(),
      regressionDetected: false,
      regressions: [],
      improvements: [],
      assessment: {
        status: 'warning',
        summary: '⚠️ NO BASELINE: No baseline available for comparison',
        recommendations: ['Consider running baseline tests to establish performance benchmarks'],
      },
      ciGateStatus: {
        passed: true,
        reason: 'No baseline to compare against',
        canProceed: true,
      },
    };
  }

  /**
   * Get baseline for a test
   */
  private getBaseline(testName: string): BaselineEntry | null {
    const baselines = this.baselineCache.get(testName) || [];

    if (baselines.length < this.config.minBaselineSamples) {
      return null;
    }

    // Return the most recent baseline
    return baselines[baselines.length - 1];
  }

  /**
   * Update baseline with new results
   */
  private async updateBaseline(result: PerformanceTestResult): Promise<void> {
    const baseline: BaselineEntry = {
      config: result.config,
      metrics: result.results.metrics,
      summary: result.results.summary,
      timestamp: result.metadata.timestamp,
      testId: result.metadata.testId,
      environment: result.metadata.environment,
    };

    const baselines = this.baselineCache.get(result.config.name) || [];
    baselines.push(baseline);

    // Keep only the most recent baselines
    if (baselines.length > 20) {
      baselines.splice(0, baselines.length - 20);
    }

    this.baselineCache.set(result.config.name, baselines);
    this.saveBaseline(result.config.name, baselines);

    console.log(`✅ Baseline updated for test: ${result.config.name}`);
  }

  /**
   * Store regression report
   */
  private async storeRegressionReport(report: RegressionReport): Promise<void> {
    const fileName = `${report.testName}-${new Date().toISOString().replace(/[:.]/g, '-')}-regression.json`;
    const filePath = join(this.config.reportsDir, fileName);

    const content = JSON.stringify(report, null, 2);
    writeFileSync(filePath, content);

    console.log(`📄 Regression report stored: ${filePath}`);
  }

  /**
   * Generate summary report
   */
  private async generateSummaryReport(reports: RegressionReport[]): Promise<void> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const fileName = `performance-regression-summary-${timestamp}.md`;
    const filePath = join(this.config.reportsDir, fileName);

    let content = `# Performance Regression Summary Report\n\n`;
    content += `**Generated:** ${new Date().toISOString()}\n`;
    content += `**Total Tests:** ${reports.length}\n\n`;

    const passedTests = reports.filter((r) => r.ciGateStatus.passed).length;
    const failedTests = reports.length - passedTests;

    content += `## Executive Summary\n\n`;
    content += `- **Passed:** ${passedTests}/${reports.length} tests\n`;
    content += `- **Failed:** ${failedTests} tests\n`;
    content += `- **Regressions Detected:** ${reports.filter((r) => r.regressionDetected).length} tests\n\n`;

    // Test results table
    content += `## Test Results\n\n`;
    content += `| Test Name | Status | Regressions | Improvements |\n`;
    content += `|-----------|--------|-------------|-------------|\n`;

    for (const report of reports) {
      const status = report.ciGateStatus.passed ? '✅ PASS' : '❌ FAIL';
      const regressions = report.regressions.length;
      const improvements = report.improvements.length;
      content += `| ${report.testName} | ${status} | ${regressions} | ${improvements} |\n`;
    }

    // Detailed regression information
    const regressionReports = reports.filter((r) => r.regressionDetected);
    if (regressionReports.length > 0) {
      content += `\n## Regression Details\n\n`;

      for (const report of regressionReports) {
        content += `### ${report.testName}\n\n`;
        content += `**Status:** ${report.assessment.status.toUpperCase()}\n`;
        content += `**Summary:** ${report.assessment.summary}\n\n`;

        if (report.regressions.length > 0) {
          content += `**Regressions:**\n`;
          for (const regression of report.regressions) {
            content += `- ${regression.metric}: ${regression.current} (baseline: ${regression.baseline}, change: ${regression.changePercentage.toFixed(1)}%) [${regression.severity.toUpperCase()}]\n`;
          }
          content += `\n`;
        }

        if (report.improvements.length > 0) {
          content += `**Improvements:**\n`;
          for (const improvement of report.improvements) {
            content += `- ${improvement.metric}: ${improvement.current} (baseline: ${improvement.baseline}, improvement: ${improvement.changePercentage.toFixed(1)}%)\n`;
          }
          content += `\n`;
        }

        content += `**Recommendations:**\n`;
        for (const recommendation of report.assessment.recommendations) {
          content += `- ${recommendation}\n`;
        }
        content += `\n`;
      }
    }

    writeFileSync(filePath, content);
    console.log(`📊 Summary report generated: ${filePath}`);
  }

  /**
   * Send notifications
   */
  private async sendNotifications(reports: RegressionReport[]): Promise<void> {
    const failedReports = reports.filter((r) => !r.ciGateStatus.passed);

    if (failedReports.length === 0) {
      return; // No notifications needed for passing tests
    }

    const message = this.buildNotificationMessage(reports);

    // Send Slack notification if configured
    if (this.config.notifications?.slack) {
      await this.sendSlackNotification(message);
    }

    // Send email notification if configured
    if (this.config.notifications?.email) {
      await this.sendEmailNotification(message);
    }
  }

  /**
   * Build notification message
   */
  private buildNotificationMessage(reports: RegressionReport[]): string {
    const failedReports = reports.filter((r) => !r.ciGateStatus.passed);
    const totalTests = reports.length;

    let message = `🚨 **Performance Regression Alert**\n\n`;
    message += `**Total Tests:** ${totalTests}\n`;
    message += `**Failed Tests:** ${failedReports.length}\n`;
    message += `**Success Rate:** ${(((totalTests - failedReports.length) / totalTests) * 100).toFixed(1)}%\n\n`;

    if (failedReports.length > 0) {
      message += `**Failed Tests:**\n`;
      for (const report of failedReports) {
        message += `- ❌ ${report.testName}: ${report.assessment.summary}\n`;
      }
      message += `\n`;
    }

    return message;
  }

  /**
   * Send Slack notification
   */
  private async sendSlackNotification(message: string): Promise<void> {
    // Implementation would use fetch or a Slack SDK to send webhook
    console.log('📱 Slack notification would be sent:', message);
  }

  /**
   * Send email notification
   */
  private async sendEmailNotification(message: string): Promise<void> {
    // Implementation would use nodemailer or similar to send email
    console.log('📧 Email notification would be sent:', message);
  }

  /**
   * Load baselines from disk
   */
  private loadBaselines(): void {
    try {
      const baselineFiles = readdirSync(this.config.baselineDir);

      for (const file of baselineFiles) {
        if (file.endsWith('.json')) {
          const testName = file.replace('.json', '');
          const filePath = join(this.config.baselineDir, file);
          const content = readFileSync(filePath, 'utf-8');
          const baselines = JSON.parse(content);

          this.baselineCache.set(testName, baselines);
        }
      }
    } catch (error) {
      console.log('No existing baselines found, starting fresh');
    }
  }

  /**
   * Save baseline to disk
   */
  private saveBaseline(testName: string, baselines: BaselineEntry[]): void {
    const filePath = join(this.config.baselineDir, `${testName}.json`);
    const content = JSON.stringify(baselines, null, 2);
    writeFileSync(filePath, content);
  }

  /**
   * Ensure directories exist
   */
  private ensureDirectories(): void {
    mkdirSync(this.config.baselineDir, { recursive: true });
    mkdirSync(this.config.reportsDir, { recursive: true });
  }

  /**
   * Get CI gate status for deployment
   */
  getDeploymentGateStatus(reports: RegressionReport[]): {
    canDeploy: boolean;
    reason: string;
    blockedTests: string[];
  } {
    const failedReports = reports.filter((r) => !r.ciGateStatus.passed);

    return {
      canDeploy: failedReports.length === 0,
      reason:
        failedReports.length > 0
          ? `Performance regressions detected in ${failedReports.length} tests`
          : 'All performance tests passed',
      blockedTests: failedReports.map((r) => r.testName),
    };
  }

  /**
   * Export regression guard results for CI systems
   */
  exportCIResults(reports: RegressionReport[]): {
    exitCode: number;
    summary: string;
    artifacts: string[];
    metrics: Record<string, unknown>;
  } {
    const failedReports = reports.filter((r) => !r.ciGateStatus.passed);
    const exitCode = failedReports.length > 0 ? 1 : 0;

    const summary = `Performance Tests: ${reports.length - failedReports.length}/${reports.length} passed`;

    const artifacts = reports.map((r) =>
      join(this.config.reportsDir, `${r.testName}-${r.timestamp}-regression.json`)
    );

    const metrics: Record<string, unknown> = {};
    for (const report of reports) {
      metrics[report.testName] = {
        status: report.ciGateStatus.passed ? 'passed' : 'failed',
        regressions: report.regressions.length,
        improvements: report.improvements.length,
        assessment: report.assessment.status,
      };
    }

    return {
      exitCode,
      summary,
      artifacts,
      metrics,
    };
  }
}
