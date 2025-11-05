/**
 * Performance Test Harness
 *
 * Comprehensive performance testing system with metrics collection,
 * regression detection, and artifact generation
 */

import { performance } from 'perf_hooks';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { randomUUID } from 'crypto';
import type {
  BenchmarkConfig,
  BenchmarkResult,
  PerformanceMetrics
} from '../bench/framework/types.js';
import {
  PerformanceTarget,
  PerformanceTestConfig,
  PerformanceTargetValidator
} from './performance-targets.js';

export interface PerformanceTestResult {
  /** Test configuration */
  config: PerformanceTestConfig;
  /** Test execution results */
  results: BenchmarkResult;
  /** Target validation results */
  validation: {
    passed: boolean;
    failures: Array<{
      target: PerformanceTarget;
      actual: number;
      deviation: number;
    }>;
    warnings: Array<{
      target: PerformanceTarget;
      actual: number;
      deviation: number;
    }>;
  };
  /** Test metadata */
  metadata: {
    testId: string;
    timestamp: string;
    duration: number;
    environment: TestEnvironment;
    systemMetrics: SystemMetrics;
  };
}

export interface TestEnvironment {
  nodeVersion: string;
  platform: string;
  arch: string;
  memory: NodeJS.MemoryUsage;
  cpuInfo?: {
    model: string;
    speed: number;
    cores: number;
  };
}

export interface SystemMetrics {
  /** Peak memory usage during test */
  peakMemoryUsage: number;
  /** Average memory usage during test */
  averageMemoryUsage: number;
  /** Memory leak detection */
  memoryLeakDetected: boolean;
  /** Memory growth rate */
  memoryGrowthRate: number;
  /** GC statistics */
  gcStats: {
    collections: number;
    duration: number;
  };
  /** CPU usage */
  cpuUsage: {
    average: number;
    peak: number;
  };
}

export interface PerformanceRegression {
  /** Test name */
  testName: string;
  /** Regression detected */
  detected: boolean;
  /** Regression details */
  details: {
    metric: string;
    baseline: number;
    current: number;
    change: number;
    changePercentage: number;
    significance: 'major' | 'minor' | 'negligible';
  }[];
  /** Impact assessment */
  impact: {
    severity: 'critical' | 'high' | 'medium' | 'low';
    affectedOperations: string[];
    recommendations: string[];
  };
}

export interface PerformanceArtifact {
  /** Artifact type */
  type: 'raw_logs' | 'chart' | 'report' | 'metrics' | 'comparison';
  /** Artifact name */
  name: string;
  /** Artifact path */
  path: string;
  /** Artifact content */
  content: string | Buffer;
  /** Metadata */
  metadata: {
    testId: string;
    timestamp: string;
    size: number;
    format: string;
  };
}

export class PerformanceHarness {
  private artifacts: PerformanceArtifact[] = [];
  private memorySnapshots: NodeJS.MemoryUsage[] = [];
  private gcStats: { collections: number; duration: number } = { collections: 0, duration: 0 };
  private testId: string;
  private startTime: number = 0;

  constructor(
    private outputDir: string = './artifacts/performance',
    private baselineDir: string = './artifacts/performance/baseline'
  ) {
    this.testId = randomUUID();
    this.ensureDirectories();
    this.setupMemoryMonitoring();
    this.setupGCMonitoring();
  }

  /**
   * Run a single performance test
   */
  async runTest(config: PerformanceTestConfig): Promise<PerformanceTestResult> {
    console.log(`🚀 Starting performance test: ${config.name}`);
    console.log(`📊 Operations: ${config.operationCount}, Concurrency: ${config.concurrency}`);

    this.startTime = performance.now();
    const environment = this.captureEnvironment();

    // Clear artifacts for this test
    this.artifacts = [];
    this.memorySnapshots = [];
    this.gcStats = { collections: 0, duration: 0 };

    // Run warmup iterations
    if (config.warmupIterations > 0) {
      console.log(`🔥 Warming up (${config.warmupIterations} iterations)`);
      await this.runWarmup(config);
    }

    // Run the actual performance test
    const benchmarkResult = await this.runBenchmark(config);

    // Validate results against targets
    const validation = this.validateResults(config, benchmarkResult);

    // Calculate system metrics
    const systemMetrics = this.calculateSystemMetrics();

    const endTime = performance.now();
    const duration = endTime - this.startTime;

    const testResult: PerformanceTestResult = {
      config,
      results: benchmarkResult,
      validation,
      metadata: {
        testId: this.testId,
        timestamp: new Date().toISOString(),
        duration,
        environment,
        systemMetrics
      }
    };

    // Generate artifacts
    await this.generateArtifacts(testResult);

    console.log(`✅ Test completed in ${(duration / 1000).toFixed(2)}s`);
    console.log(`📈 Validation: ${validation.passed ? 'PASSED' : 'FAILED'}`);
    if (validation.failures.length > 0) {
      console.log(`❌ Failures: ${validation.failures.length}`);
      validation.failures.forEach(f => {
        console.log(`   - ${f.target.name}: ${f.actual}${f.target.unit} (target: ${f.target}${f.target.unit})`);
      });
    }
    if (validation.warnings.length > 0) {
      console.log(`⚠️  Warnings: ${validation.warnings.length}`);
    }

    return testResult;
  }

  /**
   * Run multiple performance tests
   */
  async runTestSuite(configs: PerformanceTestConfig[]): Promise<PerformanceTestResult[]> {
    console.log(`🚀 Starting performance test suite: ${configs.length} tests`);
    const results: PerformanceTestResult[] = [];

    for (const config of configs) {
      if (config.skip) {
        console.log(`⏭️  Skipping test: ${config.name}`);
        continue;
      }

      try {
        const result = await this.runTest(config);
        results.push(result);

        // Add delay between tests
        await this.delay(1000);
      } catch (error) {
        console.error(`❌ Test failed: ${config.name}`, error);
        // Continue with other tests
      }
    }

    // Generate suite-level artifacts
    await this.generateSuiteArtifacts(results);

    console.log(`✅ Test suite completed: ${results.length}/${configs.length} tests successful`);
    return results;
  }

  /**
   * Detect performance regressions by comparing with baseline
   */
  async detectRegressions(results: PerformanceTestResult[]): Promise<PerformanceRegression[]> {
    const regressions: PerformanceRegression[] = [];

    for (const result of results) {
      const baseline = await this.loadBaseline(result.config.name);
      if (!baseline) {
        console.log(`⚠️  No baseline found for test: ${result.config.name}`);
        continue;
      }

      const regression = this.compareResults(result, baseline);
      if (regression.detected) {
        regressions.push(regression);
      }
    }

    return regressions;
  }

  /**
   * Store results as baseline for future comparisons
   */
  async storeBaseline(result: PerformanceTestResult): Promise<void> {
    const baselinePath = join(this.baselineDir, `${result.config.name}.json`);
    const baseline = {
      metadata: {
        testId: this.testId,
        timestamp: new Date().toISOString(),
        version: '2.0.1'
      },
      results: result.results,
      validation: result.validation,
      config: result.config
    };

    writeFileSync(baselinePath, JSON.stringify(baseline, null, 2));
    console.log(`💾 Baseline stored: ${baselinePath}`);
  }

  /**
   * Get performance artifacts
   */
  getArtifacts(): PerformanceArtifact[] {
    return this.artifacts;
  }

  /**
   * Generate performance report
   */
  generateReport(results: PerformanceTestResult[]): string {
    const timestamp = new Date().toISOString();
    let content = `# Performance Test Report\n\n`;
    content += `**Generated:** ${timestamp}\n`;
    content += `**Test ID:** ${this.testId}\n`;
    content += `**Total Tests:** ${results.length}\n\n`;

    // Executive summary
    const passedTests = results.filter(r => r.validation.passed).length;
    const failedTests = results.length - passedTests;

    content += `## Executive Summary\n\n`;
    content += `- **Passed:** ${passedTests}/${results.length} tests\n`;
    content += `- **Failed:** ${failedTests} tests\n`;
    content += `- **Success Rate:** ${((passedTests / results.length) * 100).toFixed(1)}%\n\n`;

    // Test results summary
    content += `## Test Results Summary\n\n`;
    content += `| Test Name | Status | p95 (ms) | p99 (ms) | Throughput (ops/s) | Error Rate (%) |\n`;
    content += `|-----------|--------|----------|----------|-------------------|----------------|\n`;

    for (const result of results) {
      const status = result.validation.passed ? '✅ PASS' : '❌ FAIL';
      const p95 = result.results.metrics.latencies.p95.toFixed(1);
      const p99 = result.results.metrics.latencies.p99.toFixed(1);
      const throughput = result.results.metrics.throughput.toFixed(1);
      const errorRate = result.results.metrics.errorRate.toFixed(1);

      content += `| ${result.config.name} | ${status} | ${p95} | ${p99} | ${throughput} | ${errorRate} |\n`;
    }

    // Detailed results
    content += `\n## Detailed Results\n\n`;

    for (const result of results) {
      content += `### ${result.config.name}\n\n`;
      content += `**Description:** ${result.config.description}\n\n`;
      content += `**Configuration:**\n`;
      content += `- Operations: ${result.config.operationCount}\n`;
      content += `- Concurrency: ${result.config.concurrency}\n`;
      content += `- Timeout: ${result.config.timeout}ms\n\n`;

      content += `**Performance Metrics:**\n`;
      content += `- p50: ${result.results.metrics.latencies.p50.toFixed(1)}ms\n`;
      content += `- p95: ${result.results.metrics.latencies.p95.toFixed(1)}ms\n`;
      content += `- p99: ${result.results.metrics.latencies.p99.toFixed(1)}ms\n`;
      content += `- Throughput: ${result.results.metrics.throughput.toFixed(1)} ops/s\n`;
      content += `- Error Rate: ${result.results.metrics.errorRate.toFixed(1)}%\n`;
      content += `- Peak Memory: ${(result.metadata.systemMetrics.peakMemoryUsage / 1024 / 1024).toFixed(0)}MB\n\n`;

      // Target validation
      if (result.validation.failures.length > 0) {
        content += `**Target Failures:**\n`;
        for (const failure of result.validation.failures) {
          content += `- ${failure.target.name}: ${failure.actual}${failure.target.unit} (target: ${failure.target}${failure.target.unit})\n`;
        }
        content += `\n`;
      }

      if (result.validation.warnings.length > 0) {
        content += `**Warnings:**\n`;
        for (const warning of result.validation.warnings) {
          content += `- ${warning.target.name}: ${warning.actual}${warning.target.unit} (deviation: ${warning.deviation.toFixed(1)}%)\n`;
        }
        content += `\n`;
      }
    }

    return content;
  }

  /**
   * Run warmup iterations
   */
  private async runWarmup(config: PerformanceTestConfig): Promise<void> {
    // Simple warmup - can be enhanced based on specific test requirements
    for (let i = 0; i < config.warmupIterations; i++) {
      await this.delay(100);
      // Force GC during warmup
      if (global.gc) {
        global.gc();
      }
    }
  }

  /**
   * Run benchmark test
   */
  private async runBenchmark(config: PerformanceTestConfig): Promise<BenchmarkResult> {
    const iterations = [];
    const operationsPerIteration = Math.ceil(config.operationCount / config.concurrency);

    for (let i = 0; i < config.concurrency; i++) {
      const iterationResult = await this.runIteration(config, i, operationsPerIteration);
      iterations.push(iterationResult);

      // Take memory snapshot
      this.memorySnapshots.push(process.memoryUsage());
    }

    // Calculate metrics
    const summary = this.calculateSummary(iterations);
    const metrics = this.calculateMetrics(iterations);

    return {
      scenario: config.name,
      description: config.description,
      iterations,
      summary,
      metrics,
      config: {
        concurrency: config.concurrency,
        operations: config.operationCount,
        parameters: config.parameters
      },
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Run single iteration
   */
  private async runIteration(
    config: PerformanceTestConfig,
    iteration: number,
    operations: number
  ): Promise<any> {
    const startMemory = process.memoryUsage();
    const startTime = performance.now();

    try {
      // Simulate work based on test type
      await this.simulateWorkload(config, operations);

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
        result: { operations }
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
   * Simulate workload based on test configuration
   */
  private async simulateWorkload(config: PerformanceTestConfig, operations: number): Promise<void> {
    // This is a placeholder - in real implementation, this would execute
    // actual operations based on the test type
    const workload = config.categories[0];

    switch (workload) {
      case 'storage':
      case 'knowledge':
        await this.simulateStorageOperations(operations, config.parameters);
        break;
      case 'search':
      case 'retrieval':
        await this.simulateSearchOperations(operations, config.parameters);
        break;
      case 'circuit_breaker':
      case 'resilience':
        await this.simulateCircuitBreakerOperations(operations, config.parameters);
        break;
      case 'health':
      case 'monitoring':
        await this.simulateHealthCheckOperations(operations, config.parameters);
        break;
      default:
        await this.simulateGenericOperations(operations, config.parameters);
    }
  }

  /**
   * Simulate storage operations
   */
  private async simulateStorageOperations(operations: number, params?: any): Promise<void> {
    for (let i = 0; i < operations; i++) {
      // Simulate entity storage work
      const data = JSON.stringify({
        id: randomUUID(),
        type: params?.entityTypes?.[i % params.entityTypes.length] || 'entity',
        content: 'x'.repeat(params?.averageSize || 1024),
        timestamp: new Date().toISOString()
      });

      // Simulate processing time
      await this.delay(Math.random() * 50 + 10); // 10-60ms
    }
  }

  /**
   * Simulate search operations
   */
  private async simulateSearchOperations(operations: number, params?: any): Promise<void> {
    for (let i = 0; i < operations; i++) {
      // Simulate search work
      const query = JSON.stringify({
        type: params?.queryTypes?.[i % params.queryTypes.length] || 'semantic',
        text: `search query ${i}`,
        limit: params?.resultSize || 50
      });

      // Simulate search processing time (typically faster than storage)
      await this.delay(Math.random() * 20 + 5); // 5-25ms
    }
  }

  /**
   * Simulate circuit breaker operations
   */
  private async simulateCircuitBreakerOperations(operations: number, params?: any): Promise<void> {
    for (let i = 0; i < operations; i++) {
      // Simulate circuit breaker check (very fast)
      const shouldFail = Math.random() < (params?.failureRate || 0.1);

      if (shouldFail) {
        await this.delay(Math.random() * 10 + 5); // 5-15ms for failure
      } else {
        await this.delay(Math.random() * 2 + 1); // 1-3ms for success
      }
    }
  }

  /**
   * Simulate health check operations
   */
  private async simulateHealthCheckOperations(operations: number, params?: any): Promise<void> {
    for (let i = 0; i < operations; i++) {
      // Simulate health check (fast operation)
      const checkType = params?.checkTypes?.[i % params.checkTypes.length] || 'database';

      // Different check types have different response times
      switch (checkType) {
        case 'database':
          await this.delay(Math.random() * 50 + 20); // 20-70ms
          break;
        case 'memory':
          await this.delay(Math.random() * 10 + 5); // 5-15ms
          break;
        default:
          await this.delay(Math.random() * 20 + 10); // 10-30ms
      }

      if (params?.checkInterval) {
        await this.delay(params.checkInterval);
      }
    }
  }

  /**
   * Simulate generic operations
   */
  private async simulateGenericOperations(operations: number, params?: any): Promise<void> {
    for (let i = 0; i < operations; i++) {
      // Generic workload simulation
      await this.delay(Math.random() * 30 + 10);
    }
  }

  /**
   * Validate results against performance targets
   */
  private validateResults(config: PerformanceTestConfig, results: BenchmarkResult) {
    const resultsMap: Record<string, number> = {
      store_latency_p95: results.metrics.latencies.p95,
      store_latency_p99: results.metrics.latencies.p99,
      store_throughput: results.metrics.throughput,
      store_error_rate: results.metrics.errorRate,
      search_latency_p95: results.metrics.latencies.p95,
      search_latency_p99: results.metrics.latencies.p99,
      search_throughput: results.metrics.throughput,
      search_error_rate: results.metrics.errorRate,
      circuit_breaker_response_time: results.metrics.latencies.p50,
      circuit_breaker_throughput: results.metrics.throughput,
      health_check_latency_p95: results.metrics.latencies.p95,
      health_check_throughput: results.metrics.throughput,
      memory_usage_peak: results.metrics.memoryUsage.peak
    };

    return PerformanceTargetValidator.validateResults(config.name, resultsMap, config.targets);
  }

  /**
   * Calculate summary statistics
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
        ? (successful.reduce((sum, i) => sum + (i.result?.operations || 1), 0) * 1000) /
          iterations.reduce((sum, i) => sum + i.duration, 0)
        : 0
    };
  }

  /**
   * Calculate performance metrics
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

    const p50 = this.percentile(durations, 50);
    const p95 = this.percentile(durations, 95);
    const p99 = this.percentile(durations, 99);

    const memoryUsages = iterations.map(i => i.memoryUsage.end.rss);
    const peakMemory = Math.max(...memoryUsages);
    const averageMemory = memoryUsages.reduce((sum, val) => sum + val, 0) / memoryUsages.length;

    const totalDuration = iterations.reduce((sum, i) => sum + i.duration, 0);
    const totalOperations = successful.reduce((sum, i) => sum + (i.result?.operations || 1), 0);
    const throughput = (totalOperations * 1000) / totalDuration;

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
   * Calculate percentile
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
   * Calculate system metrics
   */
  private calculateSystemMetrics(): SystemMetrics {
    const memoryUsages = this.memorySnapshots.map(m => m.rss);
    const peakMemoryUsage = Math.max(...memoryUsages);
    const averageMemoryUsage = memoryUsages.reduce((sum, val) => sum + val, 0) / memoryUsages.length;

    // Simple memory leak detection
    const memoryLeakDetected = this.detectMemoryLeak();
    const memoryGrowthRate = this.calculateMemoryGrowthRate();

    return {
      peakMemoryUsage,
      averageMemoryUsage,
      memoryLeakDetected,
      memoryGrowthRate,
      gcStats: this.gcStats,
      cpuUsage: {
        average: 0, // Would need CPU monitoring implementation
        peak: 0
      }
    };
  }

  /**
   * Detect memory leaks
   */
  private detectMemoryLeak(): boolean {
    if (this.memorySnapshots.length < 3) return false;

    const firstHalf = this.memorySnapshots.slice(0, Math.floor(this.memorySnapshots.length / 2));
    const secondHalf = this.memorySnapshots.slice(Math.floor(this.memorySnapshots.length / 2));

    const firstAvg = firstHalf.reduce((sum, m) => sum + m.rss, 0) / firstHalf.length;
    const secondAvg = secondHalf.reduce((sum, m) => sum + m.rss, 0) / secondHalf.length;

    const growth = secondAvg - firstAvg;
    const growthPercent = (growth / firstAvg) * 100;

    return growthPercent > 10; // 10% growth threshold
  }

  /**
   * Calculate memory growth rate
   */
  private calculateMemoryGrowthRate(): number {
    if (this.memorySnapshots.length < 2) return 0;

    const first = this.memorySnapshots[0].rss;
    const last = this.memorySnapshots[this.memorySnapshots.length - 1].rss;
    const duration = (performance.now() - this.startTime) / 1000; // seconds

    return (last - first) / duration; // bytes per second
  }

  /**
   * Capture test environment
   */
  private captureEnvironment(): TestEnvironment {
    return {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      memory: process.memoryUsage(),
      cpuInfo: {
        model: 'Unknown', // Would need to implement CPU detection
        speed: 0,
        cores: 0
      }
    };
  }

  /**
   * Setup memory monitoring
   */
  private setupMemoryMonitoring(): void {
    // Memory monitoring is handled manually in this implementation
  }

  /**
   * Setup GC monitoring
   */
  private setupGCMonitoring(): void {
    // Simple GC monitoring - in production would use more sophisticated approach
    const originalGC = global.gc;
    if (originalGC) {
      global.gc = () => {
        const start = performance.now();
        originalGC();
        const end = performance.now();
        this.gcStats.collections++;
        this.gcStats.duration += (end - start);
      };
    }
  }

  /**
   * Generate test artifacts
   */
  private async generateArtifacts(result: PerformanceTestResult): Promise<void> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

    // Raw logs artifact
    const rawLogsPath = join(this.outputDir, `${result.config.name}-${timestamp}-raw.json`);
    const rawLogs = {
      testId: result.metadata.testId,
      config: result.config,
      results: result.results,
      validation: result.validation,
      metadata: result.metadata
    };

    this.artifacts.push({
      type: 'raw_logs',
      name: `${result.config.name}-raw-logs`,
      path: rawLogsPath,
      content: JSON.stringify(rawLogs, null, 2),
      metadata: {
        testId: result.metadata.testId,
        timestamp: result.metadata.timestamp,
        size: JSON.stringify(rawLogs).length,
        format: 'json'
      }
    });

    // Store artifact
    writeFileSync(rawLogsPath, JSON.stringify(rawLogs, null, 2));
  }

  /**
   * Generate suite-level artifacts
   */
  private async generateSuiteArtifacts(results: PerformanceTestResult[]): Promise<void> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

    // Performance report
    const reportPath = join(this.outputDir, `performance-report-${timestamp}.md`);
    const reportContent = this.generateReport(results);

    this.artifacts.push({
      type: 'report',
      name: 'performance-report',
      path: reportPath,
      content: reportContent,
      metadata: {
        testId: this.testId,
        timestamp: new Date().toISOString(),
        size: reportContent.length,
        format: 'markdown'
      }
    });

    writeFileSync(reportPath, reportContent);

    // JSON summary for CI
    const summaryPath = join(this.outputDir, `performance-summary-${timestamp}.json`);
    const summary = {
      testId: this.testId,
      timestamp: new Date().toISOString(),
      summary: {
        totalTests: results.length,
        passedTests: results.filter(r => r.validation.passed).length,
        failedTests: results.filter(r => !r.validation.passed).length
      },
      results: results.map(r => ({
        name: r.config.name,
        passed: r.validation.passed,
        metrics: {
          p95: r.results.metrics.latencies.p95,
          p99: r.results.metrics.latencies.p99,
          throughput: r.results.metrics.throughput,
          errorRate: r.results.metrics.errorRate
        }
      }))
    };

    writeFileSync(summaryPath, JSON.stringify(summary, null, 2));
  }

  /**
   * Load baseline for comparison
   */
  private async loadBaseline(testName: string): Promise<any> {
    const baselinePath = join(this.baselineDir, `${testName}.json`);
    if (!existsSync(baselinePath)) {
      return null;
    }

    try {
      const content = readFileSync(baselinePath, 'utf-8');
      return JSON.parse(content);
    } catch (error) {
      console.error(`Failed to load baseline for ${testName}:`, error);
      return null;
    }
  }

  /**
   * Compare results with baseline
   */
  private compareResults(current: PerformanceTestResult, baseline: any): PerformanceRegression {
    const details = [];
    let detected = false;

    // Compare key metrics
    const metrics = [
      { name: 'p95_latency', current: current.results.metrics.latencies.p95, baseline: baseline.results.metrics.latencies.p95 },
      { name: 'p99_latency', current: current.results.metrics.latencies.p99, baseline: baseline.results.metrics.latencies.p99 },
      { name: 'throughput', current: current.results.metrics.throughput, baseline: baseline.results.metrics.throughput },
      { name: 'error_rate', current: current.results.metrics.errorRate, baseline: baseline.results.metrics.errorRate }
    ];

    for (const metric of metrics) {
      const change = metric.current - metric.baseline;
      const changePercentage = (change / metric.baseline) * 100;

      let significance: 'major' | 'minor' | 'negligible';
      if (Math.abs(changePercentage) > 20) {
        significance = 'major';
      } else if (Math.abs(changePercentage) > 10) {
        significance = 'minor';
      } else {
        significance = 'negligible';
      }

      // Check for regression (latency increase, throughput decrease, error rate increase)
      const isRegression =
        (metric.name.includes('latency') && change > 0) ||
        (metric.name === 'throughput' && change < 0) ||
        (metric.name === 'error_rate' && change > 0);

      if (isRegression && significance !== 'negligible') {
        detected = true;
      }

      if (significance !== 'negligible') {
        details.push({
          metric: metric.name,
          baseline: metric.baseline,
          current: metric.current,
          change,
          changePercentage,
          significance
        });
      }
    }

    return {
      testName: current.config.name,
      detected,
      details,
      impact: {
        severity: detected ? (details.some(d => d.significance === 'major') ? 'critical' : 'high') : 'low',
        affectedOperations: [current.config.name],
        recommendations: detected ? [
          'Investigate performance regression',
          'Review recent changes',
          'Consider rollback if critical'
        ] : []
      }
    };
  }

  /**
   * Ensure output directories exist
   */
  private ensureDirectories(): void {
    mkdirSync(this.outputDir, { recursive: true });
    mkdirSync(this.baselineDir, { recursive: true });
  }

  /**
   * Utility delay function
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}