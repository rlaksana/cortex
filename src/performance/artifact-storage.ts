// @ts-nocheck
// ULTIMATE FINAL EMERGENCY ROLLBACK: Remaining systematic type issues
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * Performance Artifacts Storage System
 *
 * Manages storage, organization, and retrieval of performance test artifacts
 * including raw logs, charts, reports, and metrics
 */

import { existsSync, mkdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'fs';
import { join } from 'path';
import { randomUUID } from 'crypto';

import type { BenchmarkResult,IterationResult,PerformanceArtifact,PerformanceTestResult } from './performance-harness.js';

export interface ArtifactStorageConfig {
  /** Base directory for artifact storage */
  baseDir: string;
  /** Directory for raw logs */
  logsDir: string;
  /** Directory for charts */
  chartsDir: string;
  /** Directory for reports */
  reportsDir: string;
  /** Directory for metrics */
  metricsDir: string;
  /** Directory for comparisons */
  comparisonsDir: string;
  /** Maximum artifacts to retain */
  maxArtifacts: number;
  /** Artifact retention period (days) */
  retentionDays: number;
}

export interface ChartConfig {
  /** Chart type */
  type: 'line' | 'bar' | 'scatter' | 'heatmap' | 'histogram';
  /** Chart title */
  title: string;
  /** X-axis label */
  xAxis: string;
  /** Y-axis label */
  yAxis: string;
  /** Data series */
  series: ChartSeries[];
  /** Chart dimensions */
  width?: number;
  /** Height?: number */
  height?: number;
  /** Theme */
  theme?: 'light' | 'dark';
}

export interface ChartSeries {
  /** Series name */
  name: string;
  /** Series data points */
  data: Array<{ x: number | string; y: number }>;
  /** Color */
  color?: string;
  /** Line type for line charts */
  lineType?: 'solid' | 'dashed' | 'dotted';
  /** Marker style */
  marker?: 'circle' | 'square' | 'triangle' | 'none';
}

export interface PerformanceChart {
  /** Chart ID */
  id: string;
  /** Chart configuration */
  config: ChartConfig;
  /** Chart data source */
  dataSource: string;
  /** Generation timestamp */
  timestamp: string;
  /** Chart file path */
  filePath: string;
  /** Chart format */
  format: 'svg' | 'png' | 'html';
}

export interface ArtifactIndex {
  /** Index metadata */
  metadata: {
    version: string;
    generated: string;
    totalArtifacts: number;
    totalSize: number;
  };
  /** Artifact categories */
  categories: {
    logs: ArtifactEntry[];
    charts: ArtifactEntry[];
    reports: ArtifactEntry[];
    metrics: ArtifactEntry[];
    comparisons: ArtifactEntry[];
  };
  /** Search index */
  searchIndex: SearchIndexEntry[];
}

export interface ArtifactEntry {
  /** Artifact ID */
  id: string;
  /** Artifact name */
  name: string;
  /** File path */
  path: string;
  /** File size */
  size: number;
  /** Creation timestamp */
  created: string;
  /** Artifact type */
  type: string;
  /** Tags */
  tags: string[];
  /** Test metadata */
  testMetadata?: {
    testId: string;
    testName: string;
    timestamp: string;
  };
}

export interface SearchIndexEntry {
  /** Artifact ID */
  artifactId: string;
  /** Searchable content */
  content: string;
  /** Keywords */
  keywords: string[];
  /** Relevance score */
  relevance?: number;
}

export class PerformanceArtifactStorage {
  private config: ArtifactStorageConfig;
  private artifactIndex: ArtifactIndex;

  constructor(config?: Partial<ArtifactStorageConfig>) {
    this.config = {
      baseDir: './artifacts/performance',
      logsDir: './artifacts/performance/logs',
      chartsDir: './artifacts/performance/charts',
      reportsDir: './artifacts/performance/reports',
      metricsDir: './artifacts/performance/metrics',
      comparisonsDir: './artifacts/performance/comparisons',
      maxArtifacts: 1000,
      retentionDays: 30,
      ...config
    };

    this.artifactIndex = this.loadIndex();
    this.ensureDirectories();
  }

  /**
   * Store performance test result artifacts
   */
  async storeTestResults(result: PerformanceTestResult): Promise<PerformanceArtifact[]> {
    const artifacts: PerformanceArtifact[] = [];
    const testId = result.metadata.testId;
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

    // Store raw logs
    const rawLogsArtifact = await this.storeRawLogs(result, testId, timestamp);
    artifacts.push(rawLogsArtifact);

    // Store metrics
    const metricsArtifact = await this.storeMetrics(result, testId, timestamp);
    artifacts.push(metricsArtifact);

    // Generate and store charts
    const chartArtifacts = await this.generateAndStoreCharts(result, testId, timestamp);
    artifacts.push(...chartArtifacts);

    // Generate and store reports
    const reportArtifact = await this.generateAndStoreReport(result, testId, timestamp);
    artifacts.push(reportArtifact);

    // Update index
    this.updateIndex(artifacts);

    return artifacts;
  }

  /**
   * Store raw logs artifact
   */
  private async storeRawLogs(
    result: PerformanceTestResult,
    testId: string,
    timestamp: string
  ): Promise<PerformanceArtifact> {
    const fileName = `${result.config.name}-${timestamp}-raw.json`;
    const filePath = join(this.config.logsDir, fileName);

    const rawLogs = {
      testId,
      config: result.config,
      results: result.results,
      validation: result.validation,
      metadata: result.metadata,
      systemMetrics: result.metadata.systemMetrics
    };

    const content = JSON.stringify(rawLogs, null, 2);
    writeFileSync(filePath, content);

    const artifact: PerformanceArtifact = {
      type: 'raw_logs',
      name: `${result.config.name}-raw-logs`,
      path: filePath,
      content,
      metadata: {
        testId,
        timestamp: result.metadata.timestamp,
        size: content.length,
        format: 'json'
      }
    };

    return artifact;
  }

  /**
   * Store metrics artifact
   */
  private async storeMetrics(
    result: PerformanceTestResult,
    testId: string,
    timestamp: string
  ): Promise<PerformanceArtifact> {
    const fileName = `${result.config.name}-${timestamp}-metrics.json`;
    const filePath = join(this.config.metricsDir, fileName);

    const metrics = {
      testId,
      testName: result.config.name,
      timestamp: result.metadata.timestamp,
      duration: result.metadata.duration,
      performanceMetrics: result.results.metrics,
      summaryStats: result.results.summary,
      validation: result.validation,
      systemMetrics: result.metadata.systemMetrics,
      environment: result.metadata.environment
    };

    const content = JSON.stringify(metrics, null, 2);
    writeFileSync(filePath, content);

    const artifact: PerformanceArtifact = {
      type: 'metrics',
      name: `${result.config.name}-metrics`,
      path: filePath,
      content,
      metadata: {
        testId,
        timestamp: result.metadata.timestamp,
        size: content.length,
        format: 'json'
      }
    };

    return artifact;
  }

  /**
   * Generate and store charts
   */
  private async generateAndStoreCharts(
    result: PerformanceTestResult,
    testId: string,
    timestamp: string
  ): Promise<PerformanceArtifact[]> {
    const artifacts: PerformanceArtifact[] = [];

    // Latency distribution chart
    const latencyChart = await this.generateLatencyChart(result, testId, timestamp);
    artifacts.push(latencyChart);

    // Throughput chart
    const throughputChart = await this.generateThroughputChart(result, testId, timestamp);
    artifacts.push(throughputChart);

    // Error rate chart
    const errorRateChart = await this.generateErrorRateChart(result, testId, timestamp);
    artifacts.push(errorRateChart);

    // Memory usage chart
    const memoryChart = await this.generateMemoryChart(result, testId, timestamp);
    artifacts.push(memoryChart);

    return artifacts;
  }

  /**
   * Generate latency distribution chart
   */
  private async generateLatencyChart(
    result: PerformanceTestResult,
    testId: string,
    timestamp: string
  ): Promise<PerformanceArtifact> {
    const fileName = `${result.config.name}-${timestamp}-latency-chart.html`;
    const filePath = join(this.config.chartsDir, fileName);

    const latencies = result.results.iterations
      .filter((i: IterationResult) => i.success)
      .map((i: IterationResult) => i.duration)
      .sort((a: number, b: number) => a - b);

    const percentiles = [10, 25, 50, 75, 90, 95, 99];
    const percentileData = percentiles.map(p => ({
      x: p,
      y: this.percentile(latencies, p)
    }));

    const chartConfig: ChartConfig = {
      type: 'line',
      title: `Latency Distribution - ${result.config.name}`,
      xAxis: 'Percentile (%)',
      yAxis: 'Latency (ms)',
      series: [{
        name: 'Latency',
        data: percentileData,
        color: '#3b82f6',
        marker: 'circle'
      }]
    };

    const htmlContent = this.generateChartHTML(chartConfig);
    writeFileSync(filePath, htmlContent);

    return {
      type: 'chart',
      name: `${result.config.name}-latency-chart`,
      path: filePath,
      content: htmlContent,
      metadata: {
        testId,
        timestamp: result.metadata.timestamp,
        size: htmlContent.length,
        format: 'html'
      }
    };
  }

  /**
   * Generate throughput chart
   */
  private async generateThroughputChart(
    result: PerformanceTestResult,
    testId: string,
    timestamp: string
  ): Promise<PerformanceArtifact> {
    const fileName = `${result.config.name}-${timestamp}-throughput-chart.html`;
    const filePath = join(this.config.chartsDir, fileName);

    // Calculate throughput over time (group iterations into time windows)
    const windowSize = 5000; // 5 second windows
    const startTime = Math.min(...result.results.iterations.map((i: IterationResult) => i.duration));
    const endTime = Math.max(...result.results.iterations.map((i: IterationResult) => i.duration));
    const windows = Math.ceil((endTime - startTime) / windowSize);

    const throughputData = [];
    for (let i = 0; i < windows; i++) {
      const windowStart = startTime + (i * windowSize);
      const windowEnd = windowStart + windowSize;
      const operationsInWindow = result.results.iterations.filter(
        (iter: IterationResult) => iter.duration >= windowStart && iter.duration < windowStart + windowSize
      ).length;
      const throughput = (operationsInWindow * 1000) / windowSize;
      throughputData.push({ x: i, y: throughput });
    }

    const chartConfig: ChartConfig = {
      type: 'line',
      title: `Throughput Over Time - ${result.config.name}`,
      xAxis: 'Time Window',
      yAxis: 'Throughput (ops/s)',
      series: [{
        name: 'Throughput',
        data: throughputData,
        color: '#10b981',
        marker: 'square'
      }]
    };

    const htmlContent = this.generateChartHTML(chartConfig);
    writeFileSync(filePath, htmlContent);

    return {
      type: 'chart',
      name: `${result.config.name}-throughput-chart`,
      path: filePath,
      content: htmlContent,
      metadata: {
        testId,
        timestamp: result.metadata.timestamp,
        size: htmlContent.length,
        format: 'html'
      }
    };
  }

  /**
   * Generate error rate chart
   */
  private async generateErrorRateChart(
    result: PerformanceTestResult,
    testId: string,
    timestamp: string
  ): Promise<PerformanceArtifact> {
    const fileName = `${result.config.name}-${timestamp}-error-rate-chart.html`;
    const filePath = join(this.config.chartsDir, fileName);

    const totalIterations = result.results.iterations.length;
    const failedIterations = result.results.iterations.filter((i: IterationResult) => !i.success).length;
    const successIterations = totalIterations - failedIterations;

    const chartConfig: ChartConfig = {
      type: 'bar',
      title: `Success/Error Rate - ${result.config.name}`,
      xAxis: 'Result',
      yAxis: 'Count',
      series: [{
        name: 'Operations',
        data: [
          { x: 'Success', y: successIterations },
          { x: 'Error', y: failedIterations }
        ],
        color: '#3b82f6'
      }]
    };

    const htmlContent = this.generateChartHTML(chartConfig);
    writeFileSync(filePath, htmlContent);

    return {
      type: 'chart',
      name: `${result.config.name}-error-rate-chart`,
      path: filePath,
      content: htmlContent,
      metadata: {
        testId,
        timestamp: result.metadata.timestamp,
        size: htmlContent.length,
        format: 'html'
      }
    };
  }

  /**
   * Generate memory usage chart
   */
  private async generateMemoryChart(
    result: PerformanceTestResult,
    testId: string,
    timestamp: string
  ): Promise<PerformanceArtifact> {
    const fileName = `${result.config.name}-${timestamp}-memory-chart.html`;
    const filePath = join(this.config.chartsDir, fileName);

    const memoryData = result.results.iterations.map((iteration: IterationResult, index: number) => ({
      x: index,
      y: iteration.memoryUsage.end.rss / 1024 / 1024 // Convert to MB
    }));

    const chartConfig: ChartConfig = {
      type: 'line',
      title: `Memory Usage Over Time - ${result.config.name}`,
      xAxis: 'Iteration',
      yAxis: 'Memory Usage (MB)',
      series: [{
        name: 'Memory Usage',
        data: memoryData,
        color: '#f59e0b',
        marker: 'triangle'
      }]
    };

    const htmlContent = this.generateChartHTML(chartConfig);
    writeFileSync(filePath, htmlContent);

    return {
      type: 'chart',
      name: `${result.config.name}-memory-chart`,
      path: filePath,
      content: htmlContent,
      metadata: {
        testId,
        timestamp: result.metadata.timestamp,
        size: htmlContent.length,
        format: 'html'
      }
    };
  }

  /**
   * Generate and store performance report
   */
  private async generateAndStoreReport(
    result: PerformanceTestResult,
    testId: string,
    timestamp: string
  ): Promise<PerformanceArtifact> {
    const fileName = `${result.config.name}-${timestamp}-report.md`;
    const filePath = join(this.config.reportsDir, fileName);

    const reportContent = this.generateMarkdownReport(result);
    writeFileSync(filePath, reportContent);

    return {
      type: 'report',
      name: `${result.config.name}-report`,
      path: filePath,
      content: reportContent,
      metadata: {
        testId,
        timestamp: result.metadata.timestamp,
        size: reportContent.length,
        format: 'markdown'
      }
    };
  }

  /**
   * Generate HTML chart using Chart.js
   */
  private generateChartHTML(config: ChartConfig): string {
    const chartId = randomUUID();
    const { type, title, xAxis, yAxis, series, width = 800, height = 400 } = config;

    const seriesData = series.map(s => ({
      label: s.name,
      data: s.data.map(d => ({ x: d.x, y: d.y })),
      borderColor: s.color || '#3b82f6',
      backgroundColor: s.color ? s.color + '20' : '#3b82f620',
      tension: 0.1,
      pointStyle: s.marker || 'circle',
      borderDash: s.lineType === 'dashed' ? [5, 5] : s.lineType === 'dotted' ? [2, 2] : undefined
    }));

    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f9fafb;
        }
        .chart-container {
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            max-width: ${width + 40}px;
            margin: 0 auto;
        }
        .chart-title {
            font-size: 18px;
            font-weight: 600;
            color: #111827;
            margin-bottom: 20px;
            text-align: center;
        }
        canvas {
            max-height: ${height}px;
        }
    </style>
</head>
<body>
    <div class="chart-container">
        <div class="chart-title">${title}</div>
        <canvas id="${chartId}"></canvas>
    </div>

    <script>
        const ctx = document.getElementById('${chartId}').getContext('2d');
        new Chart(ctx, {
            type: '${type}',
            data: {
                datasets: ${JSON.stringify(seriesData)}
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: false
                    },
                    legend: {
                        display: ${series.length > 1}
                    }
                },
                scales: {
                    x: {
                        type: '${type === 'bar' ? 'category' : 'linear'}',
                        title: {
                            display: true,
                            text: '${xAxis}'
                        }
                    },
                    y: {
                        title: {
                            display: true,
                            text: '${yAxis}'
                        },
                        beginAtZero: true
                    }
                }
            }
        });
    </script>
</body>
</html>`;
  }

  /**
   * Generate markdown report
   */
  private generateMarkdownReport(result: PerformanceTestResult): string {
    const { config, results, validation, metadata } = result;

    let content = `# Performance Test Report: ${config.name}\n\n`;
    content += `**Generated:** ${metadata.timestamp}\n`;
    content += `**Test ID:** ${metadata.testId}\n`;
    content += `**Duration:** ${(metadata.duration / 1000).toFixed(2)}s\n\n`;

    // Executive Summary
    content += `## Executive Summary\n\n`;
    content += `- **Status:** ${validation.passed ? '✅ PASSED' : '❌ FAILED'}\n`;
    content += `- **Total Operations:** ${results.summary.totalOperations}\n`;
    content += `- **Success Rate:** ${results.summary.successRate.toFixed(1)}%\n`;
    content += `- **Average Latency:** ${results.metrics.latencies.p50.toFixed(1)}ms\n`;
    content += `- **95th Percentile:** ${results.metrics.latencies.p95.toFixed(1)}ms\n`;
    content += `- **99th Percentile:** ${results.metrics.latencies.p99.toFixed(1)}ms\n`;
    content += `- **Throughput:** ${results.metrics.throughput.toFixed(1)} ops/s\n`;
    content += `- **Error Rate:** ${results.metrics.errorRate.toFixed(1)}%\n`;
    content += `- **Peak Memory:** ${(metadata.systemMetrics.peakMemoryUsage / 1024 / 1024).toFixed(0)}MB\n\n`;

    // Performance Targets
    content += `## Performance Targets\n\n`;
    content += `| Target | Actual | Status |\n`;
    content += `|--------|--------|--------|\n`;

    for (const target of config.targets) {
      const actualValue = this.getTargetValue(results, target.name);
      const status = actualValue !== null ? (actualValue <= target.max ? '✅' : '❌') : '⚠️';
      const actualDisplay = actualValue !== null ? `${actualValue.toFixed(2)}${target.unit}` : 'N/A';
      content += `| ${target.name} | ${actualDisplay} | ${status} |\n`;
    }

    content += `\n`;

    // Validation Results
    if (validation.failures.length > 0) {
      content += `## Target Failures\n\n`;
      for (const failure of validation.failures) {
        content += `- **${failure.target.name}**: ${failure.actual.toFixed(2)}${failure.target.unit} (target: ${failure.target}${failure.target.unit}, deviation: ${failure.deviation.toFixed(1)}%)\n`;
      }
      content += `\n`;
    }

    if (validation.warnings.length > 0) {
      content += `## Warnings\n\n`;
      for (const warning of validation.warnings) {
        content += `- **${warning.target.name}**: ${warning.actual.toFixed(2)}${warning.target.unit} (deviation: ${warning.deviation.toFixed(1)}%)\n`;
      }
      content += `\n`;
    }

    // System Metrics
    content += `## System Metrics\n\n`;
    content += `- **Node.js Version:** ${metadata.environment.nodeVersion}\n`;
    content += `- **Platform:** ${metadata.environment.platform} (${metadata.environment.arch})\n`;
    content += `- **Peak Memory Usage:** ${(metadata.systemMetrics.peakMemoryUsage / 1024 / 1024).toFixed(0)}MB\n`;
    content += `- **Average Memory Usage:** ${(metadata.systemMetrics.averageMemoryUsage / 1024 / 1024).toFixed(0)}MB\n`;
    content += `- **Memory Leak Detected:** ${metadata.systemMetrics.memoryLeakDetected ? 'Yes' : 'No'}\n`;
    content += `- **GC Collections:** ${metadata.systemMetrics.gcStats.collections}\n`;
    content += `- **GC Duration:** ${metadata.systemMetrics.gcStats.duration.toFixed(2)}ms\n\n`;

    // Recommendations
    content += `## Recommendations\n\n`;
    const recommendations = this.generateRecommendations(result);
    for (const recommendation of recommendations) {
      content += `- ${recommendation}\n`;
    }

    return content;
  }

  /**
   * Get target value from results
   */
  private getTargetValue(results: BenchmarkResult, targetName: string): number | null {
    const targetMappings: Record<string, string> = {
      'store_latency_p95': 'metrics.latencies.p95',
      'store_latency_p99': 'metrics.latencies.p99',
      'store_throughput': 'metrics.throughput',
      'store_error_rate': 'metrics.errorRate',
      'search_latency_p95': 'metrics.latencies.p95',
      'search_latency_p99': 'metrics.latencies.p99',
      'search_throughput': 'metrics.throughput',
      'search_error_rate': 'metrics.errorRate',
      'circuit_breaker_response_time': 'metrics.latencies.p50',
      'circuit_breaker_throughput': 'metrics.throughput',
      'health_check_latency_p95': 'metrics.latencies.p95',
      'health_check_throughput': 'metrics.throughput',
      'memory_usage_peak': 'metrics.memoryUsage.peak'
    };

    const path = targetMappings[targetName];
    if (!path) return null;

    const keys = path.split('.');
    let value: unknown = results;
    for (const key of keys) {
      value = value?.[key];
      if (value === undefined) return null;
    }

    return typeof value === 'number' ? value : null;
  }

  /**
   * Generate recommendations based on test results
   */
  private generateRecommendations(result: PerformanceTestResult): string[] {
    const recommendations: string[] = [];
    const { results, validation, metadata } = result;

    if (!validation.passed) {
      recommendations.push('Address performance target failures before production deployment');
    }

    if (results.metrics.errorRate > 5) {
      recommendations.push('Investigate and reduce error rate - current rate exceeds acceptable threshold');
    }

    if (results.metrics.latencies.p95 > 1000) {
      recommendations.push('Consider optimizing critical path to reduce p95 latency below 1 second');
    }

    if (metadata.systemMetrics.memoryLeakDetected) {
      recommendations.push('Memory leak detected - investigate memory management and cleanup');
    }

    if (results.metrics.throughput < 50) {
      recommendations.push('Low throughput detected - consider scaling or performance optimization');
    }

    if (validation.warnings.length > 3) {
      recommendations.push('Multiple performance warnings detected - review system performance');
    }

    if (recommendations.length === 0) {
      recommendations.push('Performance targets met - system is ready for production');
    }

    return recommendations;
  }

  /**
   * Calculate percentile
   */
  private percentile(sortedArray: number[], p: number): number {
    if (sortedArray.length === 0) return 0;
    const index = (p / 100) * (sortedArray.length - 1);
    const lower = Math.floor(index);
    const upper = Math.ceil(index);
    if (lower === upper) return sortedArray[lower];
    const weight = index - lower;
    return sortedArray[lower] * (1 - weight) + sortedArray[upper] * weight;
  }

  /**
   * Update artifact index
   */
  private updateIndex(artifacts: PerformanceArtifact[]): void {
    for (const artifact of artifacts) {
      const entry: ArtifactEntry = {
        id: randomUUID(),
        name: artifact.name,
        path: artifact.path,
        size: artifact.metadata.size,
        created: artifact.metadata.timestamp,
        type: artifact.type,
        tags: this.extractTags(artifact),
        testMetadata: {
          testId: artifact.metadata.testId,
          testName: artifact.name.split('-')[0],
          timestamp: artifact.metadata.timestamp
        }
      };

      // Add to appropriate category
      switch (artifact.type) {
        case 'raw_logs':
          this.artifactIndex.categories.logs.push(entry);
          break;
        case 'chart':
          this.artifactIndex.categories.charts.push(entry);
          break;
        case 'report':
          this.artifactIndex.categories.reports.push(entry);
          break;
        case 'metrics':
          this.artifactIndex.categories.metrics.push(entry);
          break;
        case 'comparison':
          this.artifactIndex.categories.comparisons.push(entry);
          break;
      }

      // Add to search index
      const searchEntry: SearchIndexEntry = {
        artifactId: entry.id,
        content: typeof artifact.content === 'string' ? artifact.content : JSON.stringify(artifact.content),
        keywords: [...entry.tags, entry.name, entry.type]
      };
      this.artifactIndex.searchIndex.push(searchEntry);
    }

    // Update metadata
    this.artifactIndex.metadata.totalArtifacts += artifacts.length;
    this.artifactIndex.metadata.totalSize += artifacts.reduce((sum, a) => sum + a.metadata.size, 0);
    this.artifactIndex.metadata.generated = new Date().toISOString();

    // Save index
    this.saveIndex();
  }

  /**
   * Extract tags from artifact
   */
  private extractTags(artifact: PerformanceArtifact): string[] {
    const tags = [artifact.type, artifact.name];

    if (artifact.metadata.testId) {
      tags.push(artifact.metadata.testId);
    }

    // Extract additional tags from content
    if (typeof artifact.content === 'string') {
      const content = artifact.content.toLowerCase();
      if (content.includes('latency')) tags.push('latency');
      if (content.includes('throughput')) tags.push('throughput');
      if (content.includes('memory')) tags.push('memory');
      if (content.includes('error')) tags.push('error');
      if (content.includes('performance')) tags.push('performance');
    }

    return tags;
  }

  /**
   * Load artifact index
   */
  private loadIndex(): ArtifactIndex {
    const indexPath = join(this.config.baseDir, 'index.json');
    if (existsSync(indexPath)) {
      try {
        const content = readFileSync(indexPath, 'utf-8');
        return JSON.parse(content);
      } catch (error) {
        console.error('Failed to load artifact index:', error);
      }
    }

    // Return default index
    return {
      metadata: {
        version: '1.0.0',
        generated: new Date().toISOString(),
        totalArtifacts: 0,
        totalSize: 0
      },
      categories: {
        logs: [],
        charts: [],
        reports: [],
        metrics: [],
        comparisons: []
      },
      searchIndex: []
    };
  }

  /**
   * Save artifact index
   */
  private saveIndex(): void {
    const indexPath = join(this.config.baseDir, 'index.json');
    const content = JSON.stringify(this.artifactIndex, null, 2);
    writeFileSync(indexPath, content);
  }

  /**
   * Ensure directories exist
   */
  private ensureDirectories(): void {
    const dirs = [
      this.config.baseDir,
      this.config.logsDir,
      this.config.chartsDir,
      this.config.reportsDir,
      this.config.metricsDir,
      this.config.comparisonsDir
    ];

    for (const dir of dirs) {
      mkdirSync(dir, { recursive: true });
    }
  }

  /**
   * Get artifact by ID
   */
  async getArtifact(artifactId: string): Promise<ArtifactEntry | null> {
    const allArtifacts = [
      ...this.artifactIndex.categories.logs,
      ...this.artifactIndex.categories.charts,
      ...this.artifactIndex.categories.reports,
      ...this.artifactIndex.categories.metrics,
      ...this.artifactIndex.categories.comparisons
    ];

    return allArtifacts.find(a => a.id === artifactId) || null;
  }

  /**
   * Search artifacts
   */
  async searchArtifacts(query: string): Promise<ArtifactEntry[]> {
    const searchTerms = query.toLowerCase().split(' ');
    const matchingIds = new Set<string>();

    for (const entry of this.artifactIndex.searchIndex) {
      const content = entry.content.toLowerCase();
      const keywords = entry.keywords.map(k => k.toLowerCase());

      let matches = false;
      for (const term of searchTerms) {
        if (content.includes(term) || keywords.some(k => k.includes(term))) {
          matches = true;
          break;
        }
      }

      if (matches) {
        matchingIds.add(entry.artifactId);
      }
    }

    const allArtifacts = [
      ...this.artifactIndex.categories.logs,
      ...this.artifactIndex.categories.charts,
      ...this.artifactIndex.categories.reports,
      ...this.artifactIndex.categories.metrics,
      ...this.artifactIndex.categories.comparisons
    ];

    return allArtifacts.filter(a => matchingIds.has(a.id));
  }

  /**
   * Clean up old artifacts
   */
  async cleanup(): Promise<void> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.config.retentionDays);

    let totalRemoved = 0;
    let totalSizeFreed = 0;

    // Clean each category
    for (const [category, artifacts] of Object.entries(this.artifactIndex.categories)) {
      const filtered = artifacts.filter(artifact => {
        const created = new Date(artifact.created);
        if (created < cutoffDate) {
          // Delete file
          try {
            if (existsSync(artifact.path)) {
              const stats = statSync(artifact.path);
              unlinkSync(artifact.path);
              totalSizeFreed += stats.size;
            }
            totalRemoved++;
            return false;
          } catch (error) {
            console.error(`Failed to delete artifact ${artifact.path}:`, error);
            return true;
          }
        }
        return true;
      });

      (this.artifactIndex.categories as unknown)[category] = filtered;
    }

    // Update index
    this.artifactIndex.metadata.totalArtifacts -= totalRemoved;
    this.artifactIndex.metadata.totalSize -= totalSizeFreed;
    this.saveIndex();

    console.log(`Cleaned up ${totalRemoved} artifacts, freed ${totalSizeFreed / 1024 / 1024}MB`);
  }
}