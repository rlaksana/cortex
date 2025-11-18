/**
 * SLO Observability Load Test
 *
 * Validates that the SLO monitoring, dashboards, and alerts work correctly
 * under load by simulating realistic traffic patterns and monitoring system behavior.
 *
 * @version 1.0.0
 * @since 2025-11-14
 */

import { performance } from 'perf_hooks';
import { setTimeout } from 'timers/promises';

// Import the services we're testing
import { metricsService } from '../../src/monitoring/metrics-service.js';
import { sloTracingService } from '../../src/monitoring/slo-tracing-service.js';
import { sloDashboardService } from '../../src/monitoring/slo-dashboard-service.js';
import { sloAlertingService } from '../../src/monitoring/slo-alerting-service.js';
import { sloMetricsValidator } from '../../src/monitoring/slo-metrics-validator.js';

// ============================================================================
// Test Configuration
// ============================================================================

interface LoadTestConfig {
  duration: number; // Test duration in seconds
  concurrency: number; // Number of concurrent operations
  operationsPerSecond: number; // Target operations per second
  errorInjectionRate: number; // Percentage of operations to inject errors (0-100)
  latencyRange: { min: number; max: number }; // Latency range in milliseconds
  qpsBurstInterval: number; // Interval for QPS bursts (seconds)
  qpsBurstMultiplier: number; // Multiplier for QPS during bursts
}

const DEFAULT_CONFIG: LoadTestConfig = {
  duration: 300, // 5 minutes
  concurrency: 50,
  operationsPerSecond: 100,
  errorInjectionRate: 2, // 2% error rate
  latencyRange: { min: 50, max: 2000 },
  qpsBurstInterval: 60, // Every minute
  qpsBurstMultiplier: 2.0 // Double the QPS during bursts
};

// ============================================================================
// Load Test Class
// ============================================================================

export class SLOObservabilityLoadTest {
  private config: LoadTestConfig;
  private isRunning = false;
  private results: any = {
    totalOperations: 0,
    successfulOperations: 0,
    failedOperations: 0,
    averageLatency: 0,
    p95Latency: 0,
    p99Latency: 0,
    alertsTriggered: 0,
    dashboardUpdates: 0,
    metricsCollected: 0,
    tracesGenerated: 0
  };

  constructor(config: Partial<LoadTestConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Run the complete observability load test
   */
  async runLoadTest(): Promise<{
    success: boolean;
    results: any;
    recommendations: string[];
    issues: string[];
  }> {
    console.log(`🚀 Starting SLO Observability Load Test`);
    console.log(`   Duration: ${this.config.duration}s`);
    console.log(`   Concurrency: ${this.config.concurrency}`);
    console.log(`   Target QPS: ${this.config.operationsPerSecond}`);
    console.log(`   Error Rate: ${this.config.errorInjectionRate}%`);

    this.isRunning = true;
    const startTime = Date.now();
    const latencies: number[] = [];

    try {
      // Start monitoring collection
      this.startMonitoringCollection();

      // Run concurrent operations
      const promises: Promise<void>[] = [];
      for (let i = 0; i < this.config.concurrency; i++) {
        promises.push(this.runWorker(i, latencies));
      }

      // Wait for all workers to complete
      await Promise.all(promises);

      // Calculate final results
      this.calculateResults(latencies);

      // Validate observability system
      const validation = await this.validateObservabilitySystem();

      const endTime = Date.now();
      console.log(`✅ Load test completed in ${((endTime - startTime) / 1000).toFixed(2)}s`);

      return {
        success: validation.issues.length === 0,
        results: this.results,
        recommendations: validation.recommendations,
        issues: validation.issues
      };

    } catch (error) {
      console.error(`❌ Load test failed:`, error);
      return {
        success: false,
        results: this.results,
        recommendations: ['Fix the load test implementation before proceeding'],
        issues: [`Load test execution error: ${error}`]
      };
    } finally {
      this.isRunning = false;
    }
  }

  /**
   * Run a single worker that performs operations
   */
  private async runWorker(workerId: number, latencies: number[]): Promise<void> {
    const startTime = Date.now();
    const endTime = startTime + (this.config.duration * 1000);
    let operationCount = 0;

    while (this.isRunning && Date.now() < endTime) {
      // Calculate timing to maintain target QPS
      const targetInterval = 1000 / this.config.operationsPerSecond;
      const nextOperationTime = startTime + (operationCount * targetInterval);

      if (Date.now() < nextOperationTime) {
        await setTimeout(nextOperationTime - Date.now());
      }

      // Simulate different operation types
      const operationType = Math.random();
      let operationResult: any;

      try {
        if (operationType < 0.3) {
          // 30% Memory store operations
          operationResult = await this.simulateMemoryStoreOperation();
        } else if (operationType < 0.6) {
          // 30% Memory find operations
          operationResult = await this.simulateMemoryFindOperation();
        } else if (operationType < 0.8) {
          // 20% Qdrant operations
          operationResult = await this.simulateQdrantOperation();
        } else {
          // 20% MCP tool operations
          operationResult = await this.simulateMCPOperation();
        }

        latencies.push(operationResult.latency);
        this.results.successfulOperations++;

      } catch (error) {
        this.results.failedOperations++;
        console.warn(`Worker ${workerId} operation failed:`, error);
      }

      this.results.totalOperations++;
      operationCount++;

      // Check for burst mode
      if (operationCount % (this.config.qpsBurstInterval * this.config.operationsPerSecond) === 0) {
        await this.simulateBurstMode(workerId, latencies);
      }
    }

    console.log(`Worker ${workerId} completed ${operationCount} operations`);
  }

  /**
   * Simulate memory store operation
   */
  private async simulateMemoryStoreOperation(): Promise<{ latency: number }> {
    const startTime = performance.now();
    const span = sloTracingService.startMemoryStoreSpan('store', `memory-${Date.now()}`);

    // Simulate realistic memory store latency
    const baseLatency = this.config.latencyRange.min + Math.random() *
      (this.config.latencyRange.max - this.config.latencyRange.min);

    // Inject errors based on configured rate
    const shouldError = Math.random() * 100 < this.config.errorInjectionRate;

    await setTimeout(baseLatency);

    if (shouldError) {
      sloTracingService.logSpanEvent(span.spanId, 'error', 'Simulated storage error');
      sloTracingService.finishSpan(span.spanId, 'error');
      throw new Error('Simulated memory store error');
    }

    // Record metrics
    metricsService.recordOperation('memory_store' as any, baseLatency, true, {
      memory_id: `test-${Date.now()}`,
      duplicates_found: Math.random() > 0.8 ? 1 : 0
    });

    metricsService.recordCounter('cortex_memory_store_operations_total', 1, {
      operation_type: 'store',
      status: 'success'
    });

    sloTracingService.finishSpan(span.spanId, 'ok');

    return { latency: baseLatency };
  }

  /**
   * Simulate memory find operation
   */
  private async simulateMemoryFindOperation(): Promise<{ latency: number }> {
    const startTime = performance.now();
    const span = sloTracingService.startMemoryStoreSpan('find', `memory-${Date.now()}`);

    // Memory find operations are typically faster
    const baseLatency = this.config.latencyRange.min +
      Math.random() * ((this.config.latencyRange.max - this.config.latencyRange.min) * 0.5);

    await setTimeout(baseLatency);

    // Record metrics
    metricsService.recordOperation('memory_find' as any, baseLatency, true, {
      cache_hit: Math.random() > 0.3
    });

    metricsService.recordCounter('cortex_memory_find_operations_total', 1, {
      operation_type: 'find',
      status: 'success'
    });

    sloTracingService.finishSpan(span.spanId, 'ok');

    return { latency: baseLatency };
  }

  /**
   * Simulate Qdrant operation
   */
  private async simulateQdrantOperation(): Promise<{ latency: number }> {
    const span = sloTracingService.startQdrantSpan('search', 'test-collection');

    // Qdrant operations have higher latency
    const baseLatency = this.config.latencyRange.min * 2 +
      Math.random() * ((this.config.latencyRange.max - this.config.latencyRange.min) * 1.5);

    await setTimeout(baseLatency);

    // Record Qdrant-specific metrics
    metricsService.recordGauge('cortex_qdrant_operation_latency_ms', baseLatency, {
      operation_type: 'search',
      collection: 'test-collection'
    });

    metricsService.recordCounter('cortex_qdrant_operations_total', 1, {
      operation_type: 'search',
      status: 'success'
    });

    sloTracingService.finishSpan(span.spanId, 'ok');

    return { latency: baseLatency };
  }

  /**
   * Simulate MCP tool operation
   */
  private async simulateMCPOperation(): Promise<{ latency: number }> {
    const span = sloTracingService.startMCPToolSpan('test-tool', 1024);

    // MCP operations have variable latency
    const baseLatency = this.config.latencyRange.min * 0.5 +
      Math.random() * (this.config.latencyRange.max - this.config.latencyRange.min);

    await setTimeout(baseLatency);

    // Record MCP-specific metrics
    metricsService.recordGauge('cortex_mcp_tool_duration_seconds', baseLatency / 1000, {
      tool_name: 'test-tool',
      operation_type: 'execution'
    });

    metricsService.recordCounter('cortex_mcp_tool_executions_total', 1, {
      tool_name: 'test-tool',
      status: 'success'
    });

    sloTracingService.finishSpan(span.spanId, 'ok');

    return { latency: baseLatency };
  }

  /**
   * Simulate burst mode traffic
   */
  private async simulateBurstMode(workerId: number, latencies: number[]): Promise<void> {
    console.log(`Worker ${workerId} entering burst mode`);

    const burstOperations = Math.floor(this.config.operationsPerSecond * this.config.qpsBurstMultiplier * 0.1); // 10% of burst interval
    const burstPromises: Promise<void>[] = [];

    for (let i = 0; i < burstOperations; i++) {
      burstPromises.push(this.simulateMemoryStoreOperation().then(result => {
        latencies.push(result.latency);
      }));
    }

    await Promise.all(burstPromises);
    console.log(`Worker ${workerId} completed burst mode with ${burstOperations} operations`);
  }

  /**
   * Start monitoring collection during the test
   */
  private startMonitoringCollection(): void {
    let metricsCount = 0;
    let dashboardCount = 0;

    const metricsInterval = setInterval(() => {
      if (!this.isRunning) {
        clearInterval(metricsInterval);
        return;
      }

      // Collect metrics
      const realTimeMetrics = metricsService.getRealTimeMetrics();
      metricsCount++;
      this.results.metricsCollected++;

      // Validate metrics
      const typedMetrics = [{
        id: `test-metric-${metricsCount}`,
        name: 'cortex_test_latency',
        type: 'gauge' as const,
        category: 'performance' as const,
        value: realTimeMetrics.performance.store_p95_ms,
        timestamp: new Date().toISOString(),
        component: 'test',
        labels: {
          service: 'cortex-mcp',
          environment: 'test',
          operation_type: 'test'
        },
        dimensions: [],
        quality: {
          accuracy: 1.0,
          completeness: 1.0,
          consistency: 1.0,
          timeliness: 1.0,
          validity: 1.0,
          reliability: 1.0,
          lastValidated: new Date().toISOString()
        },
        metadata: {
          source: 'load-test',
          collectionMethod: 'active' as const
        }
      }];

      const validation = sloMetricsValidator.validateMetrics(typedMetrics);
      if (validation.invalidMetrics > 0) {
        console.warn(`⚠️  Metrics validation detected ${validation.invalidMetrics} invalid metrics`);
      }

    }, 5000); // Every 5 seconds

    const dashboardInterval = setInterval(() => {
      if (!this.isRunning) {
        clearInterval(dashboardInterval);
        return;
      }

      // Trigger dashboard updates
      const sloSummary = sloDashboardService.getSLOStatusSummary();
      dashboardCount++;
      this.results.dashboardUpdates++;

      // Check if dashboards are responding
      if (sloSummary.totalSLOs === 0) {
        console.warn('⚠️  No SLOs found in dashboard service');
      }

    }, 10000); // Every 10 seconds

    const alertInterval = setInterval(() => {
      if (!this.isRunning) {
        clearInterval(alertInterval);
        return;
      }

      // Evaluate alert rules
      const alertResults = sloAlertingService.evaluateRules();
      this.results.alertsTriggered += alertResults.newAlerts;

      if (alertResults.errors.length > 0) {
        console.warn(`⚠️  Alert evaluation errors: ${alertResults.errors.join(', ')}`);
      }

    }, 30000); // Every 30 seconds
  }

  /**
   * Calculate final results
   */
  private calculateResults(latencies: number[]): void {
    if (latencies.length === 0) {
      return;
    }

    // Sort latencies for percentile calculation
    latencies.sort((a, b) => a - b);

    this.results.averageLatency = latencies.reduce((sum, lat) => sum + lat, 0) / latencies.length;
    this.results.p95Latency = latencies[Math.floor(latencies.length * 0.95)];
    this.results.p99Latency = latencies[Math.floor(latencies.length * 0.99)];

    // Get trace statistics
    const traceStats = sloTracingService.getStatistics();
    this.results.tracesGenerated = traceStats.totalSpans;

    console.log('\n📊 Load Test Results:');
    console.log(`   Total Operations: ${this.results.totalOperations}`);
    console.log(`   Success Rate: ${((this.results.successfulOperations / this.results.totalOperations) * 100).toFixed(2)}%`);
    console.log(`   Average Latency: ${this.results.averageLatency.toFixed(2)}ms`);
    console.log(`   P95 Latency: ${this.results.p95Latency.toFixed(2)}ms`);
    console.log(`   P99 Latency: ${this.results.p99Latency.toFixed(2)}ms`);
    console.log(`   Traces Generated: ${this.results.tracesGenerated}`);
    console.log(`   Alerts Triggered: ${this.results.alertsTriggered}`);
    console.log(`   Dashboard Updates: ${this.results.dashboardUpdates}`);
  }

  /**
   * Validate the observability system
   */
  private async validateObservabilitySystem(): Promise<{
    issues: string[];
    recommendations: string[];
  }> {
    const issues: string[] = [];
    const recommendations: string[] = [];

    // Validate metrics collection
    if (this.results.metricsCollected === 0) {
      issues.push('No metrics were collected during the test');
    }

    // Validate tracing
    const traceStats = sloTracingService.getStatistics();
    if (traceStats.totalSpans === 0) {
      issues.push('No trace spans were generated during the test');
    }

    // Validate dashboards
    const dashboards = sloDashboardService.getAllDashboards();
    if (dashboards.length === 0) {
      issues.push('No dashboards are available');
    }

    // Validate alerting
    const alertRules = sloAlertingService.getAlertRules();
    if (alertRules.length === 0) {
      issues.push('No alert rules are configured');
    }

    // Performance validation
    if (this.results.p99Latency > this.config.latencyRange.max * 1.5) {
      issues.push(`P99 latency ${this.results.p99Latency.toFixed(2)}ms exceeds expected maximum`);
      recommendations.push('Investigate performance bottlenecks in the monitoring pipeline');
    }

    // Success rate validation
    const successRate = (this.results.successfulOperations / this.results.totalOperations) * 100;
    const expectedSuccessRate = 100 - this.config.errorInjectionRate;
    if (Math.abs(successRate - expectedSuccessRate) > 5) {
      issues.push(`Success rate ${successRate.toFixed(2)}% differs significantly from expected ${expectedSuccessRate}%`);
      recommendations.push('Review error injection and handling mechanisms');
    }

    // Alert validation
    if (this.results.alertsTriggered === 0 && this.config.errorInjectionRate > 0) {
      recommendations.push('Consider adjusting alert thresholds to ensure they trigger during actual issues');
    }

    // Generate general recommendations
    if (issues.length === 0) {
      recommendations.push('✅ Observability system is functioning correctly under load');
      recommendations.push('Consider running longer duration tests to validate sustained performance');
      recommendations.push('Test with higher error injection rates to validate alerting robustness');
    }

    // Check metric compliance
    const latestValidation = sloMetricsValidator.getValidationHistory(1);
    if (latestValidation.length > 0) {
      const validation = latestValidation[0];
      if (validation.invalidMetrics > 0) {
        recommendations.push(`${validation.invalidMetrics} metrics failed validation - review metric naming and labeling`);
      }
    }

    return { issues, recommendations };
  }
}

// ============================================================================
// Test Runner
// ============================================================================

export async function runSLOObservabilityLoadTest(config?: Partial<LoadTestConfig>): Promise<void> {
  const loadTest = new SLOObservabilityLoadTest(config);

  console.log('🔧 Initializing SLO Observability Load Test...\n');

  const result = await loadTest.runLoadTest();

  console.log('\n📋 Test Summary:');
  console.log(`   Success: ${result.success ? '✅' : '❌'}`);

  if (result.issues.length > 0) {
    console.log('\n❌ Issues Found:');
    result.issues.forEach(issue => console.log(`   - ${issue}`));
  }

  if (result.recommendations.length > 0) {
    console.log('\n💡 Recommendations:');
    result.recommendations.forEach(rec => console.log(`   - ${rec}`));
  }

  // Exit with appropriate code
  process.exit(result.success ? 0 : 1);
}

// Run the test if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  // Parse command line arguments for custom configuration
  const config: Partial<LoadTestConfig> = {};

  const durationIndex = process.argv.indexOf('--duration');
  if (durationIndex !== -1 && process.argv[durationIndex + 1]) {
    config.duration = parseInt(process.argv[durationIndex + 1]);
  }

  const concurrencyIndex = process.argv.indexOf('--concurrency');
  if (concurrencyIndex !== -1 && process.argv[concurrencyIndex + 1]) {
    config.concurrency = parseInt(process.argv[concurrencyIndex + 1]);
  }

  const qpsIndex = process.argv.indexOf('--qps');
  if (qpsIndex !== -1 && process.argv[qpsIndex + 1]) {
    config.operationsPerSecond = parseInt(process.argv[qpsIndex + 1]);
  }

  runSLOObservabilityLoadTest(config).catch(console.error);
}