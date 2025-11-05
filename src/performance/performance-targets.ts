/**
 * Performance Targets Configuration
 *
 * Defines performance targets and thresholds for the Cortex Memory MCP system
 */

export interface PerformanceTarget {
  /** Target name */
  name: string;
  /** Description */
  description: string;
  /** Target value */
  target: number;
  /** Maximum acceptable value */
  max: number;
  /** Unit of measurement */
  unit: string;
  /** Measurement type */
  type: 'latency' | 'throughput' | 'error_rate' | 'memory' | 'cpu';
  /** Priority level */
  priority: 'critical' | 'high' | 'medium' | 'low';
  /** Enabled status */
  enabled: boolean;
}

export interface PerformanceTestConfig {
  /** Test name */
  name: string;
  /** Test description */
  description: string;
  /** Number of operations for test */
  operationCount: number;
  /** Concurrency level */
  concurrency: number;
  /** Test duration timeout (ms) */
  timeout: number;
  /** Warmup iterations */
  warmupIterations: number;
  /** Performance targets */
  targets: PerformanceTarget[];
  /** Test categories */
  categories: string[];
  /** Skip test flag */
  skip?: boolean;
  /** Custom parameters */
  parameters?: Record<string, any>;
}

export const PERFORMANCE_TARGETS: Record<string, PerformanceTarget[]> = {
  knowledge_storage: [
    {
      name: 'store_latency_p95',
      description: '95th percentile latency for knowledge storage operations',
      target: 1000, // 1 second
      max: 2000, // 2 seconds
      unit: 'ms',
      type: 'latency',
      priority: 'critical',
      enabled: true
    },
    {
      name: 'store_latency_p99',
      description: '99th percentile latency for knowledge storage operations',
      target: 2000, // 2 seconds
      max: 5000, // 5 seconds
      unit: 'ms',
      type: 'latency',
      priority: 'critical',
      enabled: true
    },
    {
      name: 'store_throughput',
      description: 'Throughput for knowledge storage operations',
      target: 100, // 100 ops/sec
      max: 50, // minimum 50 ops/sec
      unit: 'ops/s',
      type: 'throughput',
      priority: 'high',
      enabled: true
    },
    {
      name: 'store_error_rate',
      description: 'Error rate for knowledge storage operations',
      target: 0, // 0% errors
      max: 5, // maximum 5% errors
      unit: '%',
      type: 'error_rate',
      priority: 'critical',
      enabled: true
    }
  ],

  search_retrieval: [
    {
      name: 'search_latency_p95',
      description: '95th percentile latency for search operations',
      target: 500, // 0.5 seconds
      max: 1000, // 1 second
      unit: 'ms',
      type: 'latency',
      priority: 'critical',
      enabled: true
    },
    {
      name: 'search_latency_p99',
      description: '99th percentile latency for search operations',
      target: 1000, // 1 second
      max: 2000, // 2 seconds
      unit: 'ms',
      type: 'latency',
      priority: 'critical',
      enabled: true
    },
    {
      name: 'search_throughput',
      description: 'Throughput for search operations',
      target: 200, // 200 ops/sec
      max: 100, // minimum 100 ops/sec
      unit: 'ops/s',
      type: 'throughput',
      priority: 'high',
      enabled: true
    },
    {
      name: 'search_error_rate',
      description: 'Error rate for search operations',
      target: 0, // 0% errors
      max: 2, // maximum 2% errors
      unit: '%',
      type: 'error_rate',
      priority: 'critical',
      enabled: true
    }
  ],

  circuit_breaker: [
    {
      name: 'circuit_breaker_response_time',
      description: 'Circuit breaker response time',
      target: 10, // 10ms
      max: 50, // 50ms
      unit: 'ms',
      type: 'latency',
      priority: 'critical',
      enabled: true
    },
    {
      name: 'circuit_breaker_throughput',
      description: 'Circuit breaker throughput',
      target: 10000, // 10k ops/sec
      max: 5000, // minimum 5k ops/sec
      unit: 'ops/s',
      type: 'throughput',
      priority: 'high',
      enabled: true
    }
  ],

  health_checks: [
    {
      name: 'health_check_latency_p95',
      description: '95th percentile latency for health checks',
      target: 100, // 100ms
      max: 500, // 500ms
      unit: 'ms',
      type: 'latency',
      priority: 'high',
      enabled: true
    },
    {
      name: 'health_check_throughput',
      description: 'Throughput for health checks',
      target: 1000, // 1k ops/sec
      max: 500, // minimum 500 ops/sec
      unit: 'ops/s',
      type: 'throughput',
      priority: 'medium',
      enabled: true
    }
  ],

  memory_usage: [
    {
      name: 'memory_usage_peak',
      description: 'Peak memory usage during operations',
      target: 512 * 1024 * 1024, // 512MB
      max: 1024 * 1024 * 1024, // 1GB
      unit: 'bytes',
      type: 'memory',
      priority: 'high',
      enabled: true
    },
    {
      name: 'memory_leak_detection',
      description: 'Memory leak detection over time',
      target: 10 * 1024 * 1024, // 10MB growth
      max: 50 * 1024 * 1024, // 50MB growth
      unit: 'bytes',
      type: 'memory',
      priority: 'medium',
      enabled: true
    }
  ]
};

export const PERFORMANCE_TEST_CONFIGS: PerformanceTestConfig[] = [
  {
    name: 'knowledge_storage_performance',
    description: 'Performance test for knowledge storage operations',
    operationCount: 100,
    concurrency: 10,
    timeout: 30000, // 30 seconds
    warmupIterations: 5,
    targets: PERFORMANCE_TARGETS.knowledge_storage,
    categories: ['storage', 'critical', 'knowledge'],
    parameters: {
      entityTypes: ['entity', 'observation', 'decision', 'task'],
      averageSize: 1024, // 1KB average entity size
      sizeVariance: 0.3 // 30% variance
    }
  },
  {
    name: 'search_retrieval_performance',
    description: 'Performance test for search and retrieval operations',
    operationCount: 200,
    concurrency: 20,
    timeout: 30000, // 30 seconds
    warmupIterations: 5,
    targets: PERFORMANCE_TARGETS.search_retrieval,
    categories: ['search', 'critical', 'retrieval'],
    parameters: {
      queryTypes: ['semantic', 'keyword', 'hybrid'],
      resultSize: 50, // average 50 results per query
      searchComplexity: 'medium'
    }
  },
  {
    name: 'circuit_breaker_performance',
    description: 'Performance test for circuit breaker operations',
    operationCount: 1000,
    concurrency: 100,
    timeout: 10000, // 10 seconds
    warmupIterations: 10,
    targets: PERFORMANCE_TARGETS.circuit_breaker,
    categories: ['resilience', 'critical', 'circuit_breaker'],
    parameters: {
      failureRate: 0.1, // 10% failure rate for testing
      recoveryTime: 5000, // 5 seconds recovery
      threshold: 5 // 5 failures before opening
    }
  },
  {
    name: 'health_check_performance',
    description: 'Performance test for health check operations',
    operationCount: 50,
    concurrency: 5,
    timeout: 15000, // 15 seconds
    warmupIterations: 3,
    targets: PERFORMANCE_TARGETS.health_checks,
    categories: ['monitoring', 'health', 'ops'],
    parameters: {
      checkTypes: ['database', 'memory', 'circuit_breaker', 'api'],
      checkInterval: 1000 // 1 second between checks
    }
  },
  {
    name: 'load_test_critical_operations',
    description: 'Load test for critical operations under sustained load',
    operationCount: 500,
    concurrency: 50,
    timeout: 60000, // 60 seconds
    warmupIterations: 10,
    targets: [
      ...PERFORMANCE_TARGETS.knowledge_storage.filter(t => t.priority === 'critical'),
      ...PERFORMANCE_TARGETS.search_retrieval.filter(t => t.priority === 'critical')
    ],
    categories: ['load', 'stress', 'critical'],
    parameters: {
      sustainedLoad: true,
      loadDuration: 30000, // 30 seconds of sustained load
      rampUpTime: 5000 // 5 seconds ramp-up
    }
  },
  {
    name: 'memory_usage_stress_test',
    description: 'Memory usage stress test with leak detection',
    operationCount: 1000,
    concurrency: 25,
    timeout: 120000, // 2 minutes
    warmupIterations: 20,
    targets: PERFORMANCE_TARGETS.memory_usage,
    categories: ['memory', 'stress', 'resource'],
    parameters: {
      memoryMonitorInterval: 1000, // 1 second
      leakDetectionThreshold: 50 * 1024 * 1024, // 50MB
      gcForceInterval: 10000 // Force GC every 10 seconds
    }
  }
];

export class PerformanceTargetValidator {
  /**
   * Validate performance results against targets
   */
  static validateResults(
    testName: string,
    results: Record<string, number>,
    targets: PerformanceTarget[]
  ): {
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
  } {
    const failures: Array<{
      target: PerformanceTarget;
      actual: number;
      deviation: number;
    }> = [];

    const warnings: Array<{
      target: PerformanceTarget;
      actual: number;
      deviation: number;
    }> = [];

    let passed = true;

    for (const target of targets.filter(t => t.enabled)) {
      const actual = results[target.name];
      if (actual === undefined) {
        warnings.push({
          target,
          actual: 0,
          deviation: 100
        });
        continue;
      }

      const deviation = this.calculateDeviation(actual, target.target, target.type);

      // Check if result exceeds maximum allowed value
      if (this.exceedsMaximum(actual, target.max, target.type)) {
        failures.push({
          target,
          actual,
          deviation
        });
        passed = false;
      }
      // Check if result deviates significantly from target
      else if (deviation > 20) { // 20% deviation threshold
        warnings.push({
          target,
          actual,
          deviation
        });
      }
    }

    return {
      passed,
      failures,
      warnings
    };
  }

  /**
   * Calculate deviation percentage from target
   */
  private static calculateDeviation(
    actual: number,
    target: number,
    type: string
  ): number {
    if (target === 0) return 0;

    switch (type) {
      case 'latency':
      case 'memory':
        // For latency and memory, lower is better
        return ((actual - target) / target) * 100;
      case 'throughput':
        // For throughput, higher is better
        return ((target - actual) / target) * 100;
      case 'error_rate':
        // For error rate, lower is better
        return ((actual - target) / target) * 100;
      default:
        return Math.abs(((actual - target) / target) * 100);
    }
  }

  /**
   * Check if value exceeds maximum allowed
   */
  private static exceedsMaximum(actual: number, max: number, type: string): boolean {
    switch (type) {
      case 'throughput':
        // For throughput, actual should be >= max (minimum threshold)
        return actual < max;
      default:
        // For other metrics, actual should be <= max
        return actual > max;
    }
  }

  /**
   * Get performance targets for a test category
   */
  static getTargetsForCategory(category: string): PerformanceTarget[] {
    switch (category) {
      case 'storage':
      case 'knowledge':
        return PERFORMANCE_TARGETS.knowledge_storage;
      case 'search':
      case 'retrieval':
        return PERFORMANCE_TARGETS.search_retrieval;
      case 'circuit_breaker':
      case 'resilience':
        return PERFORMANCE_TARGETS.circuit_breaker;
      case 'health':
      case 'monitoring':
        return PERFORMANCE_TARGETS.health_checks;
      case 'memory':
      case 'resource':
        return PERFORMANCE_TARGETS.memory_usage;
      default:
        return [];
    }
  }

  /**
   * Get performance test configuration by name
   */
  static getTestConfig(name: string): PerformanceTestConfig | undefined {
    return PERFORMANCE_TEST_CONFIGS.find(config => config.name === name);
  }

  /**
   * Get all performance test configurations
   */
  static getAllTestConfigs(): PerformanceTestConfig[] {
    return PERFORMANCE_TEST_CONFIGS;
  }

  /**
   * Get test configurations by category
   */
  static getTestConfigsByCategory(category: string): PerformanceTestConfig[] {
    return PERFORMANCE_TEST_CONFIGS.filter(config =>
      config.categories.includes(category)
    );
  }
}