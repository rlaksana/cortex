/**
 * CSV Export Utility
 *
 * Export benchmark results to CSV format for analysis and reporting
 */

import { writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import type {
  BenchmarkResult,
  PerformanceMetrics,
  BenchmarkComparison,
  PerformanceChange
} from '../framework/types.js';

export class CSVExporter {
  private readonly outputDir: string;

  constructor(outputDir: string = './artifacts/bench') {
    this.outputDir = outputDir;
    mkdirSync(this.outputDir, { recursive: true });
  }

  /**
   * Export benchmark results to CSV
   */
  exportResults(results: BenchmarkResult[], filename?: string): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const csvFilename = filename || `benchmark-results-${timestamp}.csv`;
    const filepath = join(this.outputDir, csvFilename);

    const csvContent = this.generateResultsCSV(results);
    writeFileSync(filepath, csvContent);

    console.log(`📊 CSV exported: ${filepath}`);
    return filepath;
  }

  /**
   * Export performance metrics to CSV
   */
  exportMetrics(results: BenchmarkResult[], filename?: string): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const csvFilename = filename || `performance-metrics-${timestamp}.csv`;
    const filepath = join(this.outputDir, csvFilename);

    const csvContent = this.generateMetricsCSV(results);
    writeFileSync(filepath, csvContent);

    console.log(`📈 Metrics CSV exported: ${filepath}`);
    return filepath;
  }

  /**
   * Export detailed iteration data to CSV
   */
  exportIterations(results: BenchmarkResult[], filename?: string): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const csvFilename = filename || `iteration-data-${timestamp}.csv`;
    const filepath = join(this.outputDir, csvFilename);

    const csvContent = this.generateIterationsCSV(results);
    writeFileSync(filepath, csvContent);

    console.log(`🔬 Iterations CSV exported: ${filepath}`);
    return filepath;
  }

  /**
   * Export SLA compliance report to CSV
   */
  exportSLACompliance(results: BenchmarkResult[], slaTargets: Record<string, number>, filename?: string): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const csvFilename = filename || `sla-compliance-${timestamp}.csv`;
    const filepath = join(this.outputDir, csvFilename);

    const csvContent = this.generateSLACSV(results, slaTargets);
    writeFileSync(filepath, csvContent);

    console.log(`📋 SLA compliance CSV exported: ${filepath}`);
    return filepath;
  }

  /**
   * Export benchmark comparison to CSV
   */
  exportComparison(comparison: BenchmarkComparison, filename?: string): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const csvFilename = filename || `benchmark-comparison-${timestamp}.csv`;
    const filepath = join(this.outputDir, csvFilename);

    const csvContent = this.generateComparisonCSV(comparison);
    writeFileSync(filepath, csvContent);

    console.log(`🔍 Comparison CSV exported: ${filepath}`);
    return filepath;
  }

  /**
   * Generate CSV content for benchmark results
   */
  private generateResultsCSV(results: BenchmarkResult[]): string {
    const headers = [
      'Scenario',
      'Description',
      'Timestamp',
      'Total Operations',
      'Successful Operations',
      'Failed Operations',
      'Average Duration (ms)',
      'Throughput (ops/s)',
      'p50 Latency (ms)',
      'p95 Latency (ms)',
      'p99 Latency (ms)',
      'Min Latency (ms)',
      'Max Latency (ms)',
      'Error Rate (%)',
      'Peak Memory (MB)',
      'Average Memory (MB)',
      'Concurrency',
      'Batch Size',
      'Operation Count'
    ];

    const rows = [headers.join(',')];

    for (const result of results) {
      const memoryPeakMB = (result.metrics.memoryUsage.peak / 1024 / 1024).toFixed(2);
      const memoryAvgMB = (result.metrics.memoryUsage.average / 1024 / 1024).toFixed(2);

      rows.push([
        `"${result.scenario}"`,
        `"${result.description}"`,
        `"${result.timestamp}"`,
        result.summary.totalOperations,
        result.summary.totalOperations - result.summary.errors,
        result.summary.errors,
        result.summary.averageDuration.toFixed(2),
        result.metrics.throughput.toFixed(2),
        result.metrics.latencies.p50.toFixed(2),
        result.metrics.latencies.p95.toFixed(2),
        result.metrics.latencies.p99.toFixed(2),
        result.metrics.latencies.min.toFixed(2),
        result.metrics.latencies.max.toFixed(2),
        result.metrics.errorRate.toFixed(2),
        memoryPeakMB,
        memoryAvgMB,
        result.config.concurrency || 1,
        result.config.dataConfig?.itemCount || 1,
        result.config.operations || 1
      ].join(','));
    }

    return rows.join('\n');
  }

  /**
   * Generate CSV content for performance metrics
   */
  private generateMetricsCSV(results: BenchmarkResult[]): string {
    const headers = [
      'Scenario',
      'Metric Type',
      'Metric Name',
      'Value',
      'Unit',
      'Target',
      'Compliance',
      'Timestamp'
    ];

    const rows = [headers.join(',')];

    // Define SLA targets for common metrics
    const slaTargets: Record<string, Record<string, { target: number; unit: string }>> = {
      latency: {
        p50: { target: 200, unit: 'ms' },
        p95: { target: 800, unit: 'ms' },
        p99: { target: 2000, unit: 'ms' }
      },
      throughput: {
        operations: { target: 50, unit: 'ops/s' }
      },
      errorRate: {
        percentage: { target: 1, unit: '%' }
      }
    };

    for (const result of results) {
      // Latency metrics
      const latencyMetrics = [
        { name: 'p50', value: result.metrics.latencies.p50 },
        { name: 'p95', value: result.metrics.latencies.p95 },
        { name: 'p99', value: result.metrics.latencies.p99 },
        { name: 'min', value: result.metrics.latencies.min },
        { name: 'max', value: result.metrics.latencies.max }
      ];

      for (const metric of latencyMetrics) {
        const target = slaTargets.latency[metric.name]?.target || null;
        const compliance = target ? (metric.value <= target ? '✓' : '✗') : 'N/A';

        rows.push([
          `"${result.scenario}"`,
          'latency',
          metric.name,
          metric.value.toFixed(2),
          'ms',
          target?.toString() || 'N/A',
          compliance,
          `"${result.timestamp}"`
        ]);
      }

      // Throughput metrics
      rows.push([
        `"${result.scenario}"`,
        'throughput',
        'operations',
        result.metrics.throughput.toFixed(2),
        'ops/s',
        slaTargets.throughput.operations.target.toString(),
        result.metrics.throughput >= slaTargets.throughput.operations.target ? '✓' : '✗',
        `"${result.timestamp}"`
      ]);

      // Error rate metrics
      rows.push([
        `"${result.scenario}"`,
        'errorRate',
        'percentage',
        result.metrics.errorRate.toFixed(2),
        '%',
        slaTargets.errorRate.percentage.target.toString(),
        result.metrics.errorRate <= slaTargets.errorRate.percentage.target ? '✓' : '✗',
        `"${result.timestamp}"`
      ]);

      // Memory metrics
      rows.push([
        `"${result.scenario}"`,
        'memory',
        'peak',
        (result.metrics.memoryUsage.peak / 1024 / 1024).toFixed(2),
        'MB',
        'N/A',
        'N/A',
        `"${result.timestamp}"`
      ]);

      rows.push([
        `"${result.scenario}"`,
        'memory',
        'average',
        (result.metrics.memoryUsage.average / 1024 / 1024).toFixed(2),
        'MB',
        'N/A',
        'N/A',
        `"${result.timestamp}"`
      ]);
    }

    return rows.join('\n');
  }

  /**
   * Generate CSV content for detailed iteration data
   */
  private generateIterationsCSV(results: BenchmarkResult[]): string {
    const headers = [
      'Scenario',
      'Iteration',
      'Duration (ms)',
      'Success',
      'Error Message',
      'Memory Start (MB)',
      'Memory End (MB)',
      'Memory Delta (MB)',
      'Heap Start (MB)',
      'Heap End (MB)',
      'Heap Delta (MB)',
      'External Start (MB)',
      'External End (MB)',
      'External Delta (MB)',
      'Timestamp'
    ];

    const rows = [headers.join(',')];

    for (const result of results) {
      for (const iteration of result.iterations) {
        const memoryStartMB = (iteration.memoryUsage.start.rss / 1024 / 1024).toFixed(2);
        const memoryEndMB = (iteration.memoryUsage.end.rss / 1024 / 1024).toFixed(2);
        const memoryDeltaMB = (iteration.memoryUsage.delta.rss / 1024 / 1024).toFixed(2);

        const heapStartMB = (iteration.memoryUsage.start.heapUsed / 1024 / 1024).toFixed(2);
        const heapEndMB = (iteration.memoryUsage.end.heapUsed / 1024 / 1024).toFixed(2);
        const heapDeltaMB = (iteration.memoryUsage.delta.heapUsed / 1024 / 1024).toFixed(2);

        const externalStartMB = (iteration.memoryUsage.start.external / 1024 / 1024).toFixed(2);
        const externalEndMB = (iteration.memoryUsage.end.external / 1024 / 1024).toFixed(2);
        const externalDeltaMB = (iteration.memoryUsage.delta.external / 1024 / 1024).toFixed(2);

        rows.push([
          `"${result.scenario}"`,
          iteration.iteration,
          iteration.duration.toFixed(2),
          iteration.success,
          iteration.error ? `"${iteration.error.replace(/"/g, '""')}"` : '',
          memoryStartMB,
          memoryEndMB,
          memoryDeltaMB,
          heapStartMB,
          heapEndMB,
          heapDeltaMB,
          externalStartMB,
          externalEndMB,
          externalDeltaMB,
          `"${result.timestamp}"`
        ]);
      }
    }

    return rows.join('\n');
  }

  /**
   * Generate CSV content for SLA compliance
   */
  private generateSLACSV(results: BenchmarkResult[], slaTargets: Record<string, number>): string {
    const headers = [
      'Scenario',
      'SLA Metric',
      'Target Value',
      'Actual Value',
      'Unit',
      'Compliance Status',
      'Deviation',
      'Deviation (%)',
      'Impact Level',
      'Timestamp'
    ];

    const rows = [headers.join(',')];

    for (const result of results) {
      const scenario = result.scenario;

      // Check various SLA metrics
      const slaChecks = [
        { metric: 'p95_latency', target: slaTargets.p95_latency || 800, actual: result.metrics.latencies.p95, unit: 'ms' },
        { metric: 'p99_latency', target: slaTargets.p99_latency || 2000, actual: result.metrics.latencies.p99, unit: 'ms' },
        { metric: 'throughput', target: slaTargets.throughput || 50, actual: result.metrics.throughput, unit: 'ops/s' },
        { metric: 'error_rate', target: slaTargets.error_rate || 1, actual: result.metrics.errorRate, unit: '%' }
      ];

      for (const check of slaChecks) {
        const deviation = check.actual - check.target;
        const deviationPercentage = (deviation / check.target) * 100;
        const compliant = deviation <= 0;
        const impactLevel = this.calculateImpactLevel(deviationPercentage, check.metric);

        rows.push([
          `"${scenario}"`,
          check.metric,
          check.target.toString(),
          check.actual.toFixed(2),
          check.unit,
          compliant ? '✓ Compliant' : '✗ Non-Compliant',
          deviation.toFixed(2),
          deviationPercentage.toFixed(1),
          impactLevel,
          `"${result.timestamp}"`
        ]);
      }
    }

    return rows.join('\n');
  }

  /**
   * Generate CSV content for benchmark comparison
   */
  private generateComparisonCSV(comparison: BenchmarkComparison): string {
    const headers = [
      'Scenario',
      'Metric',
      'Baseline Value',
      'Comparison Value',
      'Change',
      'Change (%)',
      'Significance',
      'Trend',
      'Impact Assessment'
    ];

    const rows = [headers.join(',')];

    rows.push([
      `"${comparison.metadata.baseline}"`,
      'comparison_type',
      `"${comparison.metadata.comparison}"`,
      '',
      '',
      '',
      '',
      '',
      `"${comparison.summary.overallChange}"`
    ]);

    for (const change of comparison.changes) {
      rows.push([
        `"${change.scenario}"`,
        change.metric,
        change.baseline.toFixed(2),
        change.comparison.toFixed(2),
        (change.comparison - change.baseline).toFixed(2),
        change.changePercentage.toFixed(1),
        change.significance,
        change.trend,
        this.assessImpact(change.changePercentage, change.metric)
      ]);
    }

    return rows.join('\n');
  }

  /**
   * Calculate impact level for SLA deviations
   */
  private calculateImpactLevel(deviationPercentage: number, metric: string): string {
    if (deviationPercentage <= 0) return 'No Impact';

    // Different thresholds for different metrics
    const thresholds: Record<string, { low: number; medium: number; high: number }> = {
      p95_latency: { low: 10, medium: 25, high: 50 },
      p99_latency: { low: 15, medium: 35, high: 75 },
      throughput: { low: -5, medium: -15, high: -30 }, // Negative because lower is worse
      error_rate: { low: 0.5, medium: 1, high: 2 }
    };

    const threshold = thresholds[metric] || thresholds.p95_latency;

    if (deviationPercentage <= threshold.low) return 'Low';
    if (deviationPercentage <= threshold.medium) return 'Medium';
    if (deviationPercentage <= threshold.high) return 'High';
    return 'Critical';
  }

  /**
   * Assess impact of performance changes
   */
  private assessImpact(changePercentage: number, metric: string): string {
    // For latency and error rate, positive change is bad
    // For throughput, negative change is bad
    const isNegativeImpact = ['p50_latency', 'p95_latency', 'p99_latency', 'error_rate'].includes(metric)
      ? changePercentage > 0
      : changePercentage < 0;

    const absChange = Math.abs(changePercentage);

    if (absChange < 5) return 'Minimal';
    if (absChange < 15) return 'Minor';
    if (absChange < 30) return 'Moderate';
    if (absChange < 50) return 'Significant';
    return 'Major';
  }

  /**
   * Export multiple CSV files for a comprehensive report
   */
  exportComprehensiveReport(results: BenchmarkResult[], slaTargets?: Record<string, number>): {
    results: string;
    metrics: string;
    iterations: string;
    sla?: string;
  } {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

    const exportedFiles = {
      results: this.exportResults(results, `results-${timestamp}.csv`),
      metrics: this.exportMetrics(results, `metrics-${timestamp}.csv`),
      iterations: this.exportIterations(results, `iterations-${timestamp}.csv`)
    };

    if (slaTargets) {
      exportedFiles.sla = this.exportSLACompliance(results, slaTargets, `sla-${timestamp}.csv`);
    }

    console.log(`\n📊 Comprehensive report exported:`);
    console.log(`   Results: ${exportedFiles.results}`);
    console.log(`   Metrics: ${exportedFiles.metrics}`);
    console.log(`   Iterations: ${exportedFiles.iterations}`);
    if (exportedFiles.sla) {
      console.log(`   SLA: ${exportedFiles.sla}`);
    }

    return exportedFiles;
  }
}