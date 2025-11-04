#!/usr/bin/env node

/**
 * Cortex Memory MCP - Benchmark Framework
 *
 * Core benchmark runner with configurable load testing, performance monitoring,
 * and result export capabilities.
 */

import { performance } from 'perf_hooks';
import { writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import type {
  BenchmarkConfig,
  BenchmarkResult,
  BenchmarkScenario,
  PerformanceMetrics,
  LoadTestConfig
} from './types.js';

export class BenchmarkRunner {
  private results: BenchmarkResult[] = [];
  private config: BenchmarkConfig;
  private startTime: number = 0;
  private endTime: number = 0;

  constructor(config: Partial<BenchmarkConfig> = {}) {
    this.config = {
      name: 'Cortex Memory MCP Benchmark',
      version: '2.0.0',
      outputDir: './artifacts/bench',
      warmupIterations: 3,
      benchmarkIterations: 10,
      ...config
    };
  }

  /**
   * Run a complete benchmark suite
   */
  async runSuite(scenarios: BenchmarkScenario[]): Promise<BenchmarkResult[]> {
    console.log(`🚀 Starting benchmark suite: ${this.config.name}`);
    console.log(`📊 Running ${scenarios.length} scenarios`);

    this.startTime = performance.now();
    this.results = [];

    // Ensure output directory exists
    mkdirSync(this.config.outputDir, { recursive: true });

    for (const scenario of scenarios) {
      console.log(`\n📋 Running scenario: ${scenario.name}`);
      const result = await this.runScenario(scenario);
      this.results.push(result);

      // Add delay between scenarios to prevent resource contention
      if (this.config.scenarioDelay) {
        await this.delay(this.config.scenarioDelay);
      }
    }

    this.endTime = performance.now();

    console.log(`\n✅ Benchmark suite completed in ${((this.endTime - this.startTime) / 1000).toFixed(2)}s`);

    // Generate reports
    await this.generateReports();

    return this.results;
  }

  /**
   * Run a single benchmark scenario
   */
  private async runScenario(scenario: BenchmarkScenario): Promise<BenchmarkResult> {
    const result: BenchmarkResult = {
      scenario: scenario.name,
      description: scenario.description,
      iterations: [],
      summary: {
        totalOperations: 0,
        totalDuration: 0,
        errors: 0,
        throughput: 0
      },
      metrics: {
        latencies: { p50: 0, p95: 0, p99: 0, min: 0, max: 0 },
        throughput: 0,
        errorRate: 0,
        memoryUsage: { peak: 0, average: 0 }
      },
      config: scenario.config,
      timestamp: new Date().toISOString()
    };

    // Warmup phase
    if (this.config.warmupIterations > 0) {
      console.log(`  🔥 Warming up (${this.config.warmupIterations} iterations)`);
      for (let i = 0; i < this.config.warmupIterations; i++) {
        await scenario.execute(scenario.config);
      }
    }

    // Benchmark phase
    console.log(`  🏃‍♂️ Running ${this.config.benchmarkIterations} iterations`);

    for (let i = 0; i < this.config.benchmarkIterations; i++) {
      const iterationResult = await this.runIteration(scenario, i);
      result.iterations.push(iterationResult);

      // Progress indicator
      if ((i + 1) % Math.ceil(this.config.benchmarkIterations / 4) === 0) {
        console.log(`    Progress: ${i + 1}/${this.config.benchmarkIterations}`);
      }
    }

    // Calculate summary statistics
    result.summary = this.calculateSummary(result.iterations);
    result.metrics = this.calculateMetrics(result.iterations);

    console.log(`  ✅ Completed: p50=${result.metrics.latencies.p50.toFixed(1)}ms, p95=${result.metrics.latencies.p95.toFixed(1)}ms, throughput=${result.metrics.throughput.toFixed(1)}ops/s`);

    return result;
  }

  /**
   * Run a single iteration of a scenario
   */
  private async runIteration(scenario: BenchmarkScenario, iteration: number): Promise<any> {
    const startMemory = process.memoryUsage();
    const startTime = performance.now();

    try {
      const result = await scenario.execute(scenario.config);
      const endTime = performance.now();
      const endMemory = process.memoryUsage();

      return {
        iteration,
        duration: endTime - startTime,
        success: true,
        error: null,
        memoryUsage: {
          start: startMemory,
          end: endMemory,
          delta: {
            rss: endMemory.rss - startMemory.rss,
            heapUsed: endMemory.heapUsed - startMemory.heapUsed,
            heapTotal: endMemory.heapTotal - startMemory.heapTotal,
            external: endMemory.external - startMemory.external
          }
        },
        result
      };
    } catch (error) {
      const endTime = performance.now();
      const endMemory = process.memoryUsage();

      return {
        iteration,
        duration: endTime - startTime,
        success: false,
        error: error instanceof Error ? error.message : String(error),
        memoryUsage: {
          start: startMemory,
          end: endMemory,
          delta: {
            rss: endMemory.rss - startMemory.rss,
            heapUsed: endMemory.heapUsed - startMemory.heapUsed,
            heapTotal: endMemory.heapTotal - startMemory.heapTotal,
            external: endMemory.external - startMemory.external
          }
        },
        result: null
      };
    }
  }

  /**
   * Calculate summary statistics from iterations
   */
  private calculateSummary(iterations: any[]): any {
    const successful = iterations.filter(i => i.success);
    const failed = iterations.filter(i => !i.success);

    return {
      totalOperations: iterations.length,
      totalDuration: iterations.reduce((sum, i) => sum + i.duration, 0),
      errors: failed.length,
      averageDuration: successful.length > 0
        ? successful.reduce((sum, i) => sum + i.duration, 0) / successful.length
        : 0,
      successRate: (successful.length / iterations.length) * 100,
      throughput: successful.length > 0
        ? (successful.length * 1000) / iterations.reduce((sum, i) => sum + i.duration, 0)
        : 0
    };
  }

  /**
   * Calculate performance metrics from iterations
   */
  private calculateMetrics(iterations: any[]): PerformanceMetrics {
    const successful = iterations.filter(i => i.success);
    const durations = successful.map(i => i.duration).sort((a, b) => a - b);

    if (durations.length === 0) {
      return {
        latencies: { p50: 0, p95: 0, p99: 0, min: 0, max: 0 },
        throughput: 0,
        errorRate: 100,
        memoryUsage: { peak: 0, average: 0 }
      };
    }

    // Calculate percentiles
    const p50 = this.percentile(durations, 50);
    const p95 = this.percentile(durations, 95);
    const p99 = this.percentile(durations, 99);

    // Memory usage metrics
    const memoryUsages = iterations.map(i => i.memoryUsage.end.rss);
    const peakMemory = Math.max(...memoryUsages);
    const averageMemory = memoryUsages.reduce((sum, val) => sum + val, 0) / memoryUsages.length;

    const totalDuration = iterations.reduce((sum, i) => sum + i.duration, 0);
    const throughput = (successful.length * 1000) / totalDuration;

    return {
      latencies: {
        p50,
        p95,
        p99,
        min: durations[0],
        max: durations[durations.length - 1]
      },
      throughput,
      errorRate: ((iterations.length - successful.length) / iterations.length) * 100,
      memoryUsage: {
        peak: peakMemory,
        average: averageMemory
      }
    };
  }

  /**
   * Calculate percentile from sorted array
   */
  private percentile(sortedArray: number[], p: number): number {
    const index = (p / 100) * (sortedArray.length - 1);
    const lower = Math.floor(index);
    const upper = Math.ceil(index);

    if (lower === upper) {
      return sortedArray[lower];
    }

    const weight = index - lower;
    return sortedArray[lower] * (1 - weight) + sortedArray[upper] * weight;
  }

  /**
   * Generate benchmark reports
   */
  private async generateReports(): Promise<void> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

    // JSON report
    const jsonReport = {
      metadata: {
        name: this.config.name,
        version: this.config.version,
        timestamp: new Date().toISOString(),
        totalDuration: (this.endTime - this.startTime) / 1000,
        environment: {
          nodeVersion: process.version,
          platform: process.platform,
          arch: process.arch,
          memory: process.memoryUsage()
        }
      },
      results: this.results
    };

    const jsonPath = join(this.config.outputDir, `benchmark-${timestamp}.json`);
    writeFileSync(jsonPath, JSON.stringify(jsonReport, null, 2));
    console.log(`\n📄 JSON report saved: ${jsonPath}`);

    // CSV report
    const csvPath = join(this.config.outputDir, `benchmark-${timestamp}.csv`);
    const csvContent = this.generateCSV();
    writeFileSync(csvPath, csvContent);
    console.log(`📊 CSV report saved: ${csvPath}`);

    // Markdown summary
    const mdPath = join(this.config.outputDir, `benchmark-${timestamp}.md`);
    const mdContent = this.generateMarkdown();
    writeFileSync(mdPath, mdContent);
    console.log(`📝 Markdown report saved: ${mdPath}`);
  }

  /**
   * Generate CSV format results
   */
  private generateCSV(): string {
    const headers = [
      'Scenario',
      'Description',
      'Iteration',
      'Duration (ms)',
      'Success',
      'Error',
      'Memory Start (MB)',
      'Memory End (MB)',
      'Memory Delta (MB)',
      'Throughput (ops/s)',
      'p50 Latency (ms)',
      'p95 Latency (ms)',
      'p99 Latency (ms)',
      'Error Rate (%)'
    ];

    const rows = [headers.join(',')];

    for (const result of this.results) {
      for (const iteration of result.iterations) {
        rows.push([
          result.scenario,
          `"${result.description}"`,
          iteration.iteration,
          iteration.duration.toFixed(2),
          iteration.success,
          iteration.error ? `"${iteration.error}"` : '',
          (iteration.memoryUsage.start.rss / 1024 / 1024).toFixed(2),
          (iteration.memoryUsage.end.rss / 1024 / 1024).toFixed(2),
          (iteration.memoryUsage.delta.rss / 1024 / 1024).toFixed(2),
          result.metrics.throughput.toFixed(2),
          result.metrics.latencies.p50.toFixed(2),
          result.metrics.latencies.p95.toFixed(2),
          result.metrics.latencies.p99.toFixed(2),
          result.metrics.errorRate.toFixed(2)
        ].join(','));
      }
    }

    return rows.join('\n');
  }

  /**
   * Generate Markdown summary report
   */
  private generateMarkdown(): string {
    let content = `# ${this.config.name} Report\n\n`;
    content += `**Generated:** ${new Date().toISOString()}\n`;
    content += `**Duration:** ${((this.endTime - this.startTime) / 1000).toFixed(2)}s\n\n`;

    content += `## Environment\n\n`;
    content += `- **Node.js:** ${process.version}\n`;
    content += `- **Platform:** ${process.platform} (${process.arch})\n`;
    content += `- **Memory:** ${(process.memoryUsage().rss / 1024 / 1024).toFixed(0)}MB\n\n`;

    content += `## Results Summary\n\n`;
    content += `| Scenario | p50 (ms) | p95 (ms) | p99 (ms) | Throughput (ops/s) | Error Rate (%) |\n`;
    content += `|----------|----------|----------|----------|-------------------|----------------|\n`;

    for (const result of this.results) {
      content += `| ${result.scenario} | ${result.metrics.latencies.p50.toFixed(1)} | ${result.metrics.latencies.p95.toFixed(1)} | ${result.metrics.latencies.p99.toFixed(1)} | ${result.metrics.throughput.toFixed(1)} | ${result.metrics.errorRate.toFixed(1)} |\n`;
    }

    content += `\n## Detailed Results\n\n`;

    for (const result of this.results) {
      content += `### ${result.scenario}\n\n`;
      content += `**Description:** ${result.description}\n\n`;
      content += `**Metrics:**\n`;
      content += `- p50: ${result.metrics.latencies.p50.toFixed(1)}ms\n`;
      content += `- p95: ${result.metrics.latencies.p95.toFixed(1)}ms\n`;
      content += `- p99: ${result.metrics.latencies.p99.toFixed(1)}ms\n`;
      content += `- Throughput: ${result.metrics.throughput.toFixed(1)} ops/s\n`;
      content += `- Error Rate: ${result.metrics.errorRate.toFixed(1)}%\n`;
      content += `- Peak Memory: ${(result.metrics.memoryUsage.peak / 1024 / 1024).toFixed(0)}MB\n\n`;
    }

    return content;
  }

  /**
   * Utility delay function
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get benchmark results
   */
  getResults(): BenchmarkResult[] {
    return this.results;
  }

  /**
   * Export results to specified format
   */
  exportResults(format: 'json' | 'csv' | 'markdown', outputPath?: string): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const path = outputPath || join(this.config.outputDir, `benchmark-${timestamp}.${format}`);

    let content: string;

    switch (format) {
      case 'json':
        content = JSON.stringify({
          metadata: {
            name: this.config.name,
            version: this.config.version,
            timestamp: new Date().toISOString()
          },
          results: this.results
        }, null, 2);
        break;
      case 'csv':
        content = this.generateCSV();
        break;
      case 'markdown':
        content = this.generateMarkdown();
        break;
      default:
        throw new Error(`Unsupported export format: ${format}`);
    }

    writeFileSync(path, content);
    return path;
  }
}