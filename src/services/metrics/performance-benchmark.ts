/**
 * P2-P3: Performance Benchmarking and Budget Management System
 *
 * Provides comprehensive performance benchmarking capabilities with configurable
 * workloads, resource budgeting, and trend analysis. Supports 1k/10k scale testing
 * with detailed metrics collection and performance regression detection.
 *
 * Features:
 * - Configurable benchmark workloads (1k, 10k operations)
 * - Resource budget management with CPU, memory, and I/O limits
 * - Performance regression detection and alerting
 * - Comprehensive metrics collection and analysis
 * - Baseline establishment and comparison
 * - Trend analysis and capacity planning
 *
 * @module services/metrics/performance-benchmark
 */

import { logger } from '@/utils/logger.js';

import { sliSloMonitorService } from './sli-slo-monitor.js';
import { type SystemMetrics, systemMetricsService } from './system-metrics.js';

// === Type Definitions ===

export interface BenchmarkConfig {
  /** Benchmark name and description */
  name: string;
  description: string;

  /** Workload configuration */
  workload: {
    operation_count: number; // 1000 or 10000
    operation_type: 'store' | 'find' | 'mixed';
    concurrent_operations: number;
    payload_size_bytes: number;
    think_time_ms: number;
  };

  /** Resource budgets */
  budgets: {
    max_cpu_percentage: number;
    max_memory_mb: number;
    max_disk_io_mb_per_second: number;
    max_network_io_mb_per_second: number;
    max_response_time_p95_ms: number;
    max_error_rate_percentage: number;
  };

  /** Test configuration */
  test_config: {
    warmup_duration_seconds: number;
    measurement_duration_seconds: number;
    ramp_up_duration_seconds: number;
    ramp_down_duration_seconds: boolean;
    enable_gc_collection: boolean;
    gc_collection_interval_seconds: number;
  };

  /** Success criteria */
  success_criteria: {
    min_throughput_ops_per_second: number;
    max_response_time_p99_ms: number;
    max_resource_utilization_percentage: number;
    availability_requirement: number;
  };
}

export interface BenchmarkResult {
  /** Benchmark metadata */
  benchmark_id: string;
  config: BenchmarkConfig;
  timestamp: number;
  duration_seconds: number;
  status: 'running' | 'completed' | 'failed' | 'cancelled';

  /** Workload execution */
  workload_execution: {
    total_operations: number;
    successful_operations: number;
    failed_operations: number;
    throughput_ops_per_second: number;
    average_response_time_ms: number;
    response_time_p50_ms: number;
    response_time_p95_ms: number;
    response_time_p99_ms: number;
    error_rate_percentage: number;
  };

  /** Resource utilization */
  resource_utilization: {
    cpu: {
      average_percentage: number;
      peak_percentage: number;
      budget_exceeded: boolean;
    };
    memory: {
      average_mb: number;
      peak_mb: number;
      budget_exceeded: boolean;
    };
    disk_io: {
      average_mb_per_second: number;
      peak_mb_per_second: number;
      budget_exceeded: boolean;
    };
    network_io: {
      average_mb_per_second: number;
      peak_mb_per_second: number;
      budget_exceeded: boolean;
    };
  };

  /** Performance analysis */
  performance_analysis: {
    baseline_comparison?: {
      throughput_change_percentage: number;
      response_time_change_percentage: number;
      resource_usage_change_percentage: number;
      regression_detected: boolean;
    };
    bottlenecks: Array<{
      resource: string;
      utilization_percentage: number;
      impact_level: 'low' | 'medium' | 'high' | 'critical';
      recommendations: string[];
    }>;
    efficiency_score: number; // 0-100
  };

  /** Detailed metrics */
  detailed_metrics: {
    time_series_data: Array<{
      timestamp: number;
      operations_completed: number;
      response_time_ms: number;
      cpu_percentage: number;
      memory_mb: number;
    }>;
    error_distribution: Record<string, number>;
    operation_breakdown: Record<
      string,
      {
        count: number;
        avg_response_time_ms: number;
        error_rate: number;
      }
    >;
  };

  /** System state */
  system_state: {
    baseline_metrics: SystemMetrics;
    peak_metrics: SystemMetrics;
    final_metrics: SystemMetrics;
  };
}

export interface PerformanceBaseline {
  id: string;
  name: string;
  environment: 'development' | 'staging' | 'production';
  benchmark_type: string;
  created_at: number;
  result: BenchmarkResult;
  metadata: {
    hardware_config: Record<string, unknown>;
    software_version: string;
    test_conditions: string;
  };
}

export interface PerformanceBudget {
  resource: 'cpu' | 'memory' | 'disk_io' | 'network_io' | 'response_time' | 'error_rate';
  limit: number;
  unit: string;
  current_usage: number;
  utilization_percentage: number;
  status: 'within_budget' | 'warning' | 'exceeded';
  trend: 'improving' | 'stable' | 'degrading';
  alerts: Array<{
    level: 'warning' | 'critical';
    message: string;
    timestamp: number;
  }>;
}

export interface BenchmarkSuite {
  id: string;
  name: string;
  description: string;
  benchmarks: BenchmarkConfig[];
  execution_order: 'sequential' | 'parallel';
  continue_on_failure: boolean;
  created_at: number;
  created_by: string;
}

/**
 * Performance Benchmarking Service
 */
export class PerformanceBenchmarkService {
  private activeBenchmarks: Map<string, BenchmarkResult> = new Map();
  private benchmarkHistory: BenchmarkResult[] = [];
  private baselines: Map<string, PerformanceBaseline> = new Map();
  private performanceBudgets: Map<string, PerformanceBudget> = new Map();
  private isRunning: boolean = false;

  private readonly DEFAULT_BENCHMARKS: BenchmarkConfig[] = [
    {
      name: '1K Store Operations',
      description: 'Benchmark for 1,000 store operations with small payloads',
      workload: {
        operation_count: 1000,
        operation_type: 'store',
        concurrent_operations: 10,
        payload_size_bytes: 1024, // 1KB
        think_time_ms: 0,
      },
      budgets: {
        max_cpu_percentage: 70,
        max_memory_mb: 512,
        max_disk_io_mb_per_second: 10,
        max_network_io_mb_per_second: 5,
        max_response_time_p95_ms: 500,
        max_error_rate_percentage: 1,
      },
      test_config: {
        warmup_duration_seconds: 30,
        measurement_duration_seconds: 120,
        ramp_up_duration_seconds: 10,
        ramp_down_duration_seconds: true,
        enable_gc_collection: true,
        gc_collection_interval_seconds: 30,
      },
      success_criteria: {
        min_throughput_ops_per_second: 50,
        max_response_time_p99_ms: 1000,
        max_resource_utilization_percentage: 80,
        availability_requirement: 99.5,
      },
    },
    {
      name: '1K Find Operations',
      description: 'Benchmark for 1,000 find operations with complex queries',
      workload: {
        operation_count: 1000,
        operation_type: 'find',
        concurrent_operations: 20,
        payload_size_bytes: 512, // 512B query
        think_time_ms: 100,
      },
      budgets: {
        max_cpu_percentage: 60,
        max_memory_mb: 256,
        max_disk_io_mb_per_second: 20, // Read-heavy
        max_network_io_mb_per_second: 10,
        max_response_time_p95_ms: 200,
        max_error_rate_percentage: 0.5,
      },
      test_config: {
        warmup_duration_seconds: 30,
        measurement_duration_seconds: 120,
        ramp_up_duration_seconds: 5,
        ramp_down_duration_seconds: true,
        enable_gc_collection: true,
        gc_collection_interval_seconds: 30,
      },
      success_criteria: {
        min_throughput_ops_per_second: 100,
        max_response_time_p99_ms: 500,
        max_resource_utilization_percentage: 75,
        availability_requirement: 99.8,
      },
    },
    {
      name: '10K Mixed Operations',
      description: 'Comprehensive benchmark for 10,000 mixed operations',
      workload: {
        operation_count: 10000,
        operation_type: 'mixed',
        concurrent_operations: 50,
        payload_size_bytes: 2048, // 2KB
        think_time_ms: 50,
      },
      budgets: {
        max_cpu_percentage: 80,
        max_memory_mb: 1024,
        max_disk_io_mb_per_second: 50,
        max_network_io_mb_per_second: 25,
        max_response_time_p95_ms: 1000,
        max_error_rate_percentage: 2,
      },
      test_config: {
        warmup_duration_seconds: 60,
        measurement_duration_seconds: 300, // 5 minutes
        ramp_up_duration_seconds: 30,
        ramp_down_duration_seconds: true,
        enable_gc_collection: true,
        gc_collection_interval_seconds: 60,
      },
      success_criteria: {
        min_throughput_ops_per_second: 200,
        max_response_time_p99_ms: 2000,
        max_resource_utilization_percentage: 85,
        availability_requirement: 99.0,
      },
    },
  ];

  constructor() {
    this.initializeDefaultBudgets();
    logger.info('PerformanceBenchmarkService initialized', {
      defaultBenchmarksCount: this.DEFAULT_BENCHMARKS.length,
      defaultBudgetsCount: this.performanceBudgets.size,
    });
  }

  /**
   * Initialize default performance budgets
   */
  private initializeDefaultBudgets(): void {
    const defaultBudgets: PerformanceBudget[] = [
      {
        resource: 'cpu',
        limit: 80,
        unit: '%',
        current_usage: 0,
        utilization_percentage: 0,
        status: 'within_budget',
        trend: 'stable',
        alerts: [],
      },
      {
        resource: 'memory',
        limit: 1024,
        unit: 'MB',
        current_usage: 0,
        utilization_percentage: 0,
        status: 'within_budget',
        trend: 'stable',
        alerts: [],
      },
      {
        resource: 'response_time',
        limit: 500,
        unit: 'ms',
        current_usage: 0,
        utilization_percentage: 0,
        status: 'within_budget',
        trend: 'stable',
        alerts: [],
      },
      {
        resource: 'error_rate',
        limit: 1,
        unit: '%',
        current_usage: 0,
        utilization_percentage: 0,
        status: 'within_budget',
        trend: 'stable',
        alerts: [],
      },
    ];

    defaultBudgets.forEach((budget) => {
      this.performanceBudgets.set(budget.resource, budget);
    });
  }

  /**
   * Execute performance benchmark
   */
  async executeBenchmark(config: BenchmarkConfig): Promise<BenchmarkResult> {
    const benchmarkId = `benchmark_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    const result: BenchmarkResult = {
      benchmark_id: benchmarkId,
      config,
      timestamp: Date.now(),
      duration_seconds: 0,
      status: 'running',
      workload_execution: {
        total_operations: 0,
        successful_operations: 0,
        failed_operations: 0,
        throughput_ops_per_second: 0,
        average_response_time_ms: 0,
        response_time_p50_ms: 0,
        response_time_p95_ms: 0,
        response_time_p99_ms: 0,
        error_rate_percentage: 0,
      },
      resource_utilization: {
        cpu: { average_percentage: 0, peak_percentage: 0, budget_exceeded: false },
        memory: { average_mb: 0, peak_mb: 0, budget_exceeded: false },
        disk_io: { average_mb_per_second: 0, peak_mb_per_second: 0, budget_exceeded: false },
        network_io: { average_mb_per_second: 0, peak_mb_per_second: 0, budget_exceeded: false },
      },
      performance_analysis: {
        bottlenecks: [],
        efficiency_score: 0,
      },
      detailed_metrics: {
        time_series_data: [],
        error_distribution: {},
        operation_breakdown: {},
      },
      system_state: {
        baseline_metrics: systemMetricsService.getMetrics(),
        peak_metrics: systemMetricsService.getMetrics(),
        final_metrics: systemMetricsService.getMetrics(),
      },
    };

    this.activeBenchmarks.set(benchmarkId, result);

    logger.info('Starting performance benchmark', {
      benchmarkId,
      name: config.name,
      operationCount: config.workload.operation_count,
      operationType: config.workload.operation_type,
    });

    const startTime = Date.now();

    try {
      // Execute benchmark phases
      await this.executeWarmupPhase(config, result);
      await this.executeMeasurementPhase(config, result);
      await this.executeRampDownPhase(config, result);

      // Analyze results
      await this.analyzeBenchmarkResults(result);

      result.status = 'completed';
      result.duration_seconds = Math.floor((Date.now() - startTime) / 1000);

      // Store in history
      this.benchmarkHistory.push({ ...result });
      this.activeBenchmarks.delete(benchmarkId);

      logger.info('Benchmark completed successfully', {
        benchmarkId,
        duration: result.duration_seconds,
        throughput: result.workload_execution.throughput_ops_per_second,
        efficiencyScore: result.performance_analysis.efficiency_score,
      });

      return result;
    } catch (error) {
      result.status = 'failed';
      result.duration_seconds = Math.floor((Date.now() - startTime) / 1000);

      this.benchmarkHistory.push({ ...result });
      this.activeBenchmarks.delete(benchmarkId);

      logger.error('Benchmark failed', {
        benchmarkId,
        error: error instanceof Error ? error.message : String(error),
        duration: result.duration_seconds,
      });

      throw error;
    }
  }

  /**
   * Execute warmup phase
   */
  private async executeWarmupPhase(
    config: BenchmarkConfig,
    result: BenchmarkResult
  ): Promise<void> {
    logger.debug('Starting warmup phase', {
      benchmarkId: result.benchmark_id,
      duration: config.test_config.warmup_duration_seconds,
    });

    const warmupOperations = Math.floor(config.workload.operation_count * 0.1); // 10% for warmup
    const startTime = Date.now();
    const endTime = startTime + config.test_config.warmup_duration_seconds * 1000;

    while (Date.now() < endTime) {
      await this.executeOperationBatch(config, Math.min(warmupOperations / 10, 10), result);

      // GC collection if enabled
      if (
        config.test_config.enable_gc_collection &&
        Date.now() % (config.test_config.gc_collection_interval_seconds * 1000) < 1000
      ) {
        if (global.gc) {
          global.gc();
        }
      }
    }

    logger.debug('Warmup phase completed', {
      benchmarkId: result.benchmark_id,
      actualDuration: Date.now() - startTime,
    });
  }

  /**
   * Execute measurement phase
   */
  private async executeMeasurementPhase(
    config: BenchmarkConfig,
    result: BenchmarkResult
  ): Promise<void> {
    logger.debug('Starting measurement phase', {
      benchmarkId: result.benchmark_id,
      duration: config.test_config.measurement_duration_seconds,
    });

    const startTime = Date.now();
    const endTime = startTime + config.test_config.measurement_duration_seconds * 1000;
    let operationsCompleted = 0;

    // Start metrics collection
    const metricsInterval = setInterval(() => {
      this.collectMetrics(result);
    }, 1000);

    while (Date.now() < endTime && operationsCompleted < config.workload.operation_count) {
      const batchSize = Math.min(
        config.workload.concurrent_operations,
        config.workload.operation_count - operationsCompleted
      );

      await this.executeOperationBatch(config, batchSize, result);
      operationsCompleted += batchSize;

      // Add think time
      if (config.workload.think_time_ms > 0) {
        await new Promise((resolve) => setTimeout(resolve, config.workload.think_time_ms));
      }
    }

    clearInterval(metricsInterval);

    logger.debug('Measurement phase completed', {
      benchmarkId: result.benchmark_id,
      operationsCompleted,
      actualDuration: Date.now() - startTime,
    });
  }

  /**
   * Execute ramp down phase
   */
  private async executeRampDownPhase(
    config: BenchmarkConfig,
    result: BenchmarkResult
  ): Promise<void> {
    if (!config.test_config.ramp_down_duration_seconds) {
      return;
    }

    logger.debug('Starting ramp down phase', {
      benchmarkId: result.benchmark_id,
      duration: 10, // Fixed 10 seconds for ramp down
    });

    const rampDownOperations = Math.floor(config.workload.operation_count * 0.05); // 5% for ramp down
    const startTime = Date.now();
    const endTime = startTime + 10000; // 10 seconds

    while (Date.now() < endTime) {
      await this.executeOperationBatch(config, Math.min(rampDownOperations / 10, 5), result);
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }

    logger.debug('Ramp down phase completed', {
      benchmarkId: result.benchmark_id,
      actualDuration: Date.now() - startTime,
    });
  }

  /**
   * Execute operation batch
   */
  private async executeOperationBatch(
    config: BenchmarkConfig,
    batchSize: number,
    result: BenchmarkResult
  ): Promise<void> {
    const batchStartTime = Date.now();
    const promises: Promise<unknown>[] = [];

    for (let i = 0; i < batchSize; i++) {
      promises.push(this.executeSingleOperation(config, result));
    }

    try {
      await Promise.allSettled(promises);

      const batchDuration = Date.now() - batchStartTime;
      result.workload_execution.total_operations += batchSize;

      // Update time series data
      result.detailed_metrics.time_series_data.push({
        timestamp: Date.now(),
        operations_completed: batchSize,
        response_time_ms: batchDuration / batchSize,
        cpu_percentage: this.getCurrentCPUUsage(),
        memory_mb: this.getCurrentMemoryUsage(),
      });
    } catch (error) {
      result.workload_execution.failed_operations += batchSize;
      logger.error('Operation batch failed', {
        benchmarkId: result.benchmark_id,
        batchSize,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  /**
   * Execute single operation (simulated)
   */
  private async executeSingleOperation(
    config: BenchmarkConfig,
    result: BenchmarkResult
  ): Promise<unknown> {
    const startTime = Date.now();

    try {
      // Simulate operation based on type
      let operationResult: unknown;

      switch (config.workload.operation_type) {
        case 'store':
          operationResult = await this.simulateStoreOperation(config);
          break;
        case 'find':
          operationResult = await this.simulateFindOperation(config);
          break;
        case 'mixed':
          operationResult =
            Math.random() > 0.5
              ? await this.simulateStoreOperation(config)
              : await this.simulateFindOperation(config);
          break;
        default:
          throw new Error(`Unknown operation type: ${config.workload.operation_type}`);
      }

      const responseTime = Date.now() - startTime;
      result.workload_execution.successful_operations++;

      return operationResult;
    } catch (error) {
      const responseTime = Date.now() - startTime;
      result.workload_execution.failed_operations++;

      // Track error distribution
      const errorType = (error as unknown).code || 'UNKNOWN_ERROR';
      result.detailed_metrics.error_distribution[errorType] =
        (result.detailed_metrics.error_distribution[errorType] || 0) + 1;

      throw error;
    }
  }

  /**
   * Simulate store operation
   */
  private async simulateStoreOperation(config: BenchmarkConfig): Promise<unknown> {
    // Simulate processing time based on payload size
    const processingTime = Math.random() * 50 + config.workload.payload_size_bytes / 100; // Base time + size factor
    await new Promise((resolve) => setTimeout(resolve, processingTime));

    // Simulate occasional failures (0.5% failure rate)
    if (Math.random() < 0.005) {
      throw new Error('Simulated store operation failure');
    }

    return { id: `item_${Date.now()}_${Math.random().toString(36).substr(2, 9)}` };
  }

  /**
   * Simulate find operation
   */
  private async simulateFindOperation(config: BenchmarkConfig): Promise<unknown> {
    // Simulate query processing time
    const processingTime = Math.random() * 30 + config.workload.payload_size_bytes / 200;
    await new Promise((resolve) => setTimeout(resolve, processingTime));

    // Simulate occasional failures (0.2% failure rate)
    if (Math.random() < 0.002) {
      throw new Error('Simulated find operation failure');
    }

    return {
      results: Array.from({ length: Math.floor(Math.random() * 10) + 1 }, (_, i) => ({
        id: `result_${i}`,
        score: Math.random(),
      })),
    };
  }

  /**
   * Collect current metrics
   */
  private collectMetrics(result: BenchmarkResult): void {
    const systemMetrics = systemMetricsService.getMetrics();
    const currentCPU = this.getCurrentCPUUsage();
    const currentMemory = this.getCurrentMemoryUsage();

    // Update resource utilization
    result.resource_utilization.cpu.average_percentage =
      (result.resource_utilization.cpu.average_percentage + currentCPU) / 2;
    result.resource_utilization.cpu.peak_percentage = Math.max(
      result.resource_utilization.cpu.peak_percentage,
      currentCPU
    );

    result.resource_utilization.memory.average_mb =
      (result.resource_utilization.memory.average_mb + currentMemory) / 2;
    result.resource_utilization.memory.peak_mb = Math.max(
      result.resource_utilization.memory.peak_mb,
      currentMemory
    );

    // Update peak metrics
    result.system_state.peak_metrics = systemMetrics;

    // Check budget violations
    this.checkBudgetViolations(result, currentCPU, currentMemory);
  }

  /**
   * Get current CPU usage (simulated)
   */
  private getCurrentCPUUsage(): number {
    // Simulate CPU usage based on active benchmarks
    const baseUsage = 20;
    const benchmarkLoad = this.activeBenchmarks.size * 15;
    const randomVariation = Math.random() * 10;

    return Math.min(100, baseUsage + benchmarkLoad + randomVariation);
  }

  /**
   * Get current memory usage (simulated)
   */
  private getCurrentMemoryUsage(): number {
    // Simulate memory usage
    const baseUsage = 100;
    const benchmarkLoad = this.activeBenchmarks.size * 50;
    const randomVariation = Math.random() * 20;

    return baseUsage + benchmarkLoad + randomVariation;
  }

  /**
   * Check budget violations
   */
  private checkBudgetViolations(
    result: BenchmarkResult,
    currentCPU: number,
    currentMemory: number
  ): void {
    // Check CPU budget
    if (currentCPU > result.config.budgets.max_cpu_percentage) {
      result.resource_utilization.cpu.budget_exceeded = true;
    }

    // Check memory budget
    if (currentMemory > result.config.budgets.max_memory_mb) {
      result.resource_utilization.memory.budget_exceeded = true;
    }
  }

  /**
   * Analyze benchmark results
   */
  private async analyzeBenchmarkResults(result: BenchmarkResult): Promise<void> {
    // Calculate final metrics
    this.calculateFinalMetrics(result);

    // Compare with baseline
    await this.compareWithBaseline(result);

    // Identify bottlenecks
    this.identifyBottlenecks(result);

    // Calculate efficiency score
    this.calculateEfficiencyScore(result);
  }

  /**
   * Calculate final metrics
   */
  private calculateFinalMetrics(result: BenchmarkResult): void {
    const totalOps = result.workload_execution.total_operations;
    const successfulOps = result.workload_execution.successful_operations;
    const failedOps = result.workload_execution.failed_operations;

    if (totalOps > 0) {
      result.workload_execution.error_rate_percentage = (failedOps / totalOps) * 100;
    }

    // Calculate response time percentiles from time series data
    const responseTimes = result.detailed_metrics.time_series_data.map((d) => d.response_time_ms);
    if (responseTimes.length > 0) {
      responseTimes.sort((a, b) => a - b);
      const len = responseTimes.length;

      result.workload_execution.response_time_p50_ms = responseTimes[Math.floor(len * 0.5)];
      result.workload_execution.response_time_p95_ms = responseTimes[Math.floor(len * 0.95)];
      result.workload_execution.response_time_p99_ms = responseTimes[Math.floor(len * 0.99)];
      result.workload_execution.average_response_time_ms =
        responseTimes.reduce((sum, time) => sum + time, 0) / len;
    }

    // Calculate throughput
    if (result.duration_seconds > 0) {
      result.workload_execution.throughput_ops_per_second = totalOps / result.duration_seconds;
    }
  }

  /**
   * Compare with baseline
   */
  private async compareWithBaseline(result: BenchmarkResult): Promise<void> {
    const baselineKey = `${result.config.workload.operation_type}_${result.config.workload.operation_count}`;
    const baseline = this.baselines.get(baselineKey);

    if (baseline) {
      const baselineResult = baseline.result;

      const throughputChange =
        ((result.workload_execution.throughput_ops_per_second -
          baselineResult.workload_execution.throughput_ops_per_second) /
          baselineResult.workload_execution.throughput_ops_per_second) *
        100;

      const responseTimeChange =
        ((result.workload_execution.response_time_p95_ms -
          baselineResult.workload_execution.response_time_p95_ms) /
          baselineResult.workload_execution.response_time_p95_ms) *
        100;

      const resourceChange =
        ((result.resource_utilization.cpu.average_percentage -
          baselineResult.resource_utilization.cpu.average_percentage) /
          baselineResult.resource_utilization.cpu.average_percentage) *
        100;

      result.performance_analysis.baseline_comparison = {
        throughput_change_percentage: throughputChange,
        response_time_change_percentage: responseTimeChange,
        resource_usage_change_percentage: resourceChange,
        regression_detected:
          throughputChange < -10 || responseTimeChange > 20 || resourceChange > 15,
      };
    }
  }

  /**
   * Identify bottlenecks
   */
  private identifyBottlenecks(result: BenchmarkResult): void {
    const bottlenecks = result.performance_analysis.bottlenecks;

    // CPU bottleneck
    if (result.resource_utilization.cpu.peak_percentage > 80) {
      bottlenecks.push({
        resource: 'cpu',
        utilization_percentage: result.resource_utilization.cpu.peak_percentage,
        impact_level: result.resource_utilization.cpu.peak_percentage > 95 ? 'critical' : 'high',
        recommendations: [
          'Optimize algorithms and data structures',
          'Consider horizontal scaling',
          'Profile CPU-intensive operations',
        ],
      });
    }

    // Memory bottleneck
    if (result.resource_utilization.memory.peak_mb > result.config.budgets.max_memory_mb * 0.8) {
      bottlenecks.push({
        resource: 'memory',
        utilization_percentage:
          (result.resource_utilization.memory.peak_mb / result.config.budgets.max_memory_mb) * 100,
        impact_level:
          result.resource_utilization.memory.peak_mb > result.config.budgets.max_memory_mb
            ? 'critical'
            : 'medium',
        recommendations: [
          'Optimize memory usage and data structures',
          'Implement memory pooling',
          'Consider streaming processing',
        ],
      });
    }

    // Response time bottleneck
    if (
      result.workload_execution.response_time_p95_ms >
      result.config.budgets.max_response_time_p95_ms
    ) {
      bottlenecks.push({
        resource: 'response_time',
        utilization_percentage:
          (result.workload_execution.response_time_p95_ms /
            result.config.budgets.max_response_time_p95_ms) *
          100,
        impact_level:
          result.workload_execution.response_time_p95_ms >
          result.config.budgets.max_response_time_p95_ms * 2
            ? 'critical'
            : 'high',
        recommendations: [
          'Optimize database queries',
          'Implement caching strategies',
          'Review algorithmic complexity',
        ],
      });
    }
  }

  /**
   * Calculate efficiency score
   */
  private calculateEfficiencyScore(result: BenchmarkResult): void {
    let score = 100;

    // Throughput component (30%)
    const throughputScore = Math.min(
      100,
      (result.workload_execution.throughput_ops_per_second /
        result.config.success_criteria.min_throughput_ops_per_second) *
        100
    );
    score = score * 0.7 + throughputScore * 0.3;

    // Response time component (25%)
    const responseTimeScore = Math.max(
      0,
      100 -
        ((result.workload_execution.response_time_p95_ms -
          result.config.budgets.max_response_time_p95_ms) /
          result.config.budgets.max_response_time_p95_ms) *
          100
    );
    score = score * 0.75 + responseTimeScore * 0.25;

    // Resource efficiency component (25%)
    const avgResourceUtilization =
      (result.resource_utilization.cpu.average_percentage +
        (result.resource_utilization.memory.average_mb / result.config.budgets.max_memory_mb) *
          100) /
      2;
    const resourceScore =
      avgResourceUtilization <= 80 ? 100 : Math.max(0, 100 - (avgResourceUtilization - 80) * 2);
    score = score * 0.75 + resourceScore * 0.25;

    // Error rate component (20%)
    const errorScore = Math.max(0, 100 - result.workload_execution.error_rate_percentage * 10);
    score = score * 0.8 + errorScore * 0.2;

    result.performance_analysis.efficiency_score = Math.round(score * 100) / 100;
  }

  // === Public API Methods ===

  /**
   * Get default benchmarks
   */
  getDefaultBenchmarks(): BenchmarkConfig[] {
    return this.DEFAULT_BENCHMARKS.map((config) => ({ ...config }));
  }

  /**
   * Run default benchmark
   */
  async runDefaultBenchmark(benchmarkName: string): Promise<BenchmarkResult> {
    const config = this.DEFAULT_BENCHMARKS.find((b) => b.name === benchmarkName);
    if (!config) {
      throw new Error(`Default benchmark '${benchmarkName}' not found`);
    }

    return await this.executeBenchmark(config);
  }

  /**
   * Get benchmark results
   */
  getBenchmarkResults(limit?: number, operationType?: string): BenchmarkResult[] {
    let results = [...this.benchmarkHistory];

    if (operationType) {
      results = results.filter((r) => r.config.workload.operation_type === operationType);
    }

    // Sort by timestamp (newest first)
    results.sort((a, b) => b.timestamp - a.timestamp);

    return limit ? results.slice(0, limit) : results;
  }

  /**
   * Get active benchmarks
   */
  getActiveBenchmarks(): BenchmarkResult[] {
    return Array.from(this.activeBenchmarks.values()).map((result) => ({ ...result }));
  }

  /**
   * Set performance baseline
   */
  setBaseline(
    name: string,
    environment: 'development' | 'staging' | 'production',
    result: BenchmarkResult
  ): void {
    const baseline: PerformanceBaseline = {
      id: `baseline_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      name,
      environment,
      benchmark_type: `${result.config.workload.operation_type}_${result.config.workload.operation_count}`,
      created_at: Date.now(),
      result,
      metadata: {
        hardware_config: {
          cpu_cores: 8,
          memory_gb: 16,
          disk_type: 'SSD',
        },
        software_version: '1.0.0',
        test_conditions: 'standard',
      },
    };

    const baselineKey = `${result.config.workload.operation_type}_${result.config.workload.operation_count}`;
    this.baselines.set(baselineKey, baseline);

    logger.info('Performance baseline set', {
      name,
      environment,
      baselineKey,
      efficiencyScore: result.performance_analysis.efficiency_score,
    });
  }

  /**
   * Get performance budgets
   */
  getPerformanceBudgets(): PerformanceBudget[] {
    // Update current usage
    const currentMetrics = this.collectCurrentMetrics();

    for (const [resource, budget] of this.performanceBudgets.entries()) {
      switch (resource) {
        case 'cpu':
          budget.current_usage = currentMetrics.cpu;
          break;
        case 'memory':
          budget.current_usage = currentMetrics.memory;
          break;
        case 'response_time':
          budget.current_usage = currentMetrics.response_time;
          break;
        case 'error_rate':
          budget.current_usage = currentMetrics.error_rate;
          break;
      }

      budget.utilization_percentage = (budget.current_usage / budget.limit) * 100;

      if (budget.utilization_percentage >= 100) {
        budget.status = 'exceeded';
      } else if (budget.utilization_percentage >= 80) {
        budget.status = 'warning';
      } else {
        budget.status = 'within_budget';
      }
    }

    return Array.from(this.performanceBudgets.values()).map((budget) => ({ ...budget }));
  }

  /**
   * Collect current metrics
   */
  private collectCurrentMetrics(): unknown {
    const systemMetrics = systemMetricsService.getMetrics();
    const ragStatus = sliSloMonitorService.getRAGStatus();
    const sliMetrics = sliSloMonitorService.getSLIMetrics();

    return {
      cpu: sliMetrics.resource_utilization.cpu_percentage,
      memory: sliMetrics.resource_utilization.memory_percentage,
      response_time: sliMetrics.latency.p95_ms,
      error_rate: sliMetrics.error_rate.error_rate_percentage,
    };
  }

  /**
   * Export benchmark data
   */
  exportBenchmarkData(format: 'json' | 'csv' = 'json'): string {
    const data = {
      timestamp: Date.now(),
      benchmarks: this.benchmarkHistory.map((result) => ({
        benchmark_id: result.benchmark_id,
        name: result.config.name,
        operation_type: result.config.workload.operation_type,
        operation_count: result.config.workload.operation_count,
        status: result.status,
        duration_seconds: result.duration_seconds,
        throughput: result.workload_execution.throughput_ops_per_second,
        efficiency_score: result.performance_analysis.efficiency_score,
        created_at: result.timestamp,
      })),
      baselines: Array.from(this.baselines.values()).map((baseline) => ({
        name: baseline.name,
        environment: baseline.environment,
        benchmark_type: baseline.benchmark_type,
        efficiency_score: baseline.result.performance_analysis.efficiency_score,
        created_at: baseline.created_at,
      })),
      performance_budgets: this.getPerformanceBudgets(),
    };

    if (format === 'csv') {
      return this.formatBenchmarksAsCSV(data);
    }

    return JSON.stringify(data, null, 2);
  }

  /**
   * Format benchmarks as CSV
   */
  private formatBenchmarksAsCSV(data: unknown): string {
    const headers = [
      'timestamp',
      'benchmark_id',
      'name',
      'operation_type',
      'operation_count',
      'status',
      'duration',
      'throughput',
      'efficiency_score',
    ];
    const rows = [headers.join(',')];

    data.benchmarks.forEach((benchmark: unknown) => {
      rows.push(
        [
          data.timestamp,
          benchmark.benchmark_id,
          benchmark.name,
          benchmark.operation_type,
          benchmark.operation_count,
          benchmark.status,
          benchmark.duration_seconds,
          benchmark.throughput,
          benchmark.efficiency_score,
        ].join(',')
      );
    });

    return rows.join('\n');
  }

  /**
   * Graceful shutdown
   */
  destroy(): void {
    // Cancel all active benchmarks
    for (const [benchmarkId, result] of this.activeBenchmarks.entries()) {
      result.status = 'cancelled';
      this.benchmarkHistory.push({ ...result });
    }
    this.activeBenchmarks.clear();

    logger.info('PerformanceBenchmarkService destroyed');
  }
}

// Singleton instance
export const performanceBenchmarkService = new PerformanceBenchmarkService();
