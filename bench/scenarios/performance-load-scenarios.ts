/**
 * Performance Load Scenarios for Benchmark Framework
 *
 * Integration of performance testing scenarios with the existing benchmark framework
 */

import type { BenchmarkScenario, LoadTestConfig } from '../framework/types.js';
import { PERFORMANCE_TEST_CONFIGS } from '../../src/performance/performance-targets.js';
import { randomUUID } from 'crypto';

/**
 * Convert performance test configurations to benchmark scenarios
 */
export function createPerformanceLoadScenarios(): BenchmarkScenario[] {
  const scenarios: BenchmarkScenario[] = [];

  for (const testConfig of PERFORMANCE_TEST_CONFIGS) {
    const scenario = convertTestConfigToScenario(testConfig);
    scenarios.push(scenario);
  }

  return scenarios;
}

/**
 * Convert individual test config to benchmark scenario
 */
function convertTestConfigToScenario(testConfig: any): BenchmarkScenario {
  const loadTestConfig: LoadTestConfig = {
    concurrency: testConfig.concurrency,
    operations: testConfig.operationCount,
    operationDelay: 10, // Small delay between operations
    rampUpTime: testConfig.parameters?.rampUpTime || 5000,
    dataConfig: {
      itemCount: testConfig.operationCount,
      averageItemSize: testConfig.parameters?.averageSize || 1024,
      sizeVariance: testConfig.parameters?.sizeVariance || 0.3,
      useExisting: false,
    },
    parameters: testConfig.parameters,
  };

  return {
    name: testConfig.name,
    description: testConfig.description,
    execute: async (config: LoadTestConfig) => {
      return await executePerformanceScenario(testConfig, config);
    },
    config: loadTestConfig,
    tags: testConfig.categories,
  };
}

/**
 * Execute performance scenario based on test type
 */
async function executePerformanceScenario(
  testConfig: any,
  loadConfig: LoadTestConfig
): Promise<any> {
  const startTime = performance.now();
  const results = {
    operations: [],
    errors: 0,
    totalDuration: 0,
    metrics: {
      latencies: { p50: 0, p95: 0, p99: 0, min: 0, max: 0 },
      throughput: 0,
      errorRate: 0,
    },
  };

  // Determine scenario type and execute accordingly
  const scenarioType = testConfig.categories[0];

  switch (scenarioType) {
    case 'storage':
    case 'knowledge':
    case 'entity':
    case 'observation':
    case 'decision':
    case 'task':
      await executeKnowledgeStorageScenario(testConfig, loadConfig, results);
      break;

    case 'search':
    case 'retrieval':
    case 'semantic':
    case 'keyword':
    case 'hybrid':
      await executeSearchScenario(testConfig, loadConfig, results);
      break;

    case 'circuit_breaker':
    case 'resilience':
      await executeCircuitBreakerScenario(testConfig, loadConfig, results);
      break;

    case 'health':
    case 'monitoring':
      await executeHealthCheckScenario(testConfig, loadConfig, results);
      break;

    default:
      await executeGenericScenario(testConfig, loadConfig, results);
  }

  const endTime = performance.now();
  results.totalDuration = endTime - startTime;

  // Calculate metrics
  calculateScenarioMetrics(results);

  return results;
}

/**
 * Execute knowledge storage scenario
 */
async function executeKnowledgeStorageScenario(
  testConfig: any,
  loadConfig: LoadTestConfig,
  results: any
): Promise<void> {
  const entityTypes = testConfig.parameters?.entityTypes || ['entity'];
  const averageSize = testConfig.parameters?.averageSize || 1024;
  const sizeVariance = testConfig.parameters?.sizeVariance || 0.3;

  for (let i = 0; i < loadConfig.operations; i++) {
    const operationStart = performance.now();

    try {
      // Simulate knowledge storage operation
      const entityType = entityTypes[i % entityTypes.length];
      const size = averageSize * (1 + (Math.random() - 0.5) * sizeVariance * 2);

      // Simulate processing time based on entity type and size
      let processingTime: number;
      switch (entityType) {
        case 'entity':
          processingTime = 10 + (size / 1024) * 5 + Math.random() * 20;
          break;
        case 'observation':
          processingTime = 5 + (size / 1024) * 3 + Math.random() * 15;
          break;
        case 'decision':
          processingTime = 15 + (size / 1024) * 8 + Math.random() * 25;
          break;
        case 'task':
          processingTime = 8 + (size / 1024) * 4 + Math.random() * 18;
          break;
        default:
          processingTime = 10 + Math.random() * 20;
      }

      // Simulate async operation
      await new Promise((resolve) => setTimeout(resolve, processingTime));

      const operationEnd = performance.now();
      const duration = operationEnd - operationStart;

      results.operations.push({
        index: i,
        type: 'knowledge_storage',
        subType: entityType,
        duration,
        success: true,
        size,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      const operationEnd = performance.now();
      const duration = operationEnd - operationStart;

      results.operations.push({
        index: i,
        type: 'knowledge_storage',
        duration,
        success: false,
        error: error instanceof Error ? error.message : String(error),
        timestamp: new Date().toISOString(),
      });

      results.errors++;
    }

    // Add operation delay if specified
    if (loadConfig.operationDelay && loadConfig.operationDelay > 0) {
      await new Promise((resolve) => setTimeout(resolve, loadConfig.operationDelay));
    }
  }
}

/**
 * Execute search scenario
 */
async function executeSearchScenario(
  testConfig: any,
  loadConfig: LoadTestConfig,
  results: any
): Promise<void> {
  const queryTypes = testConfig.parameters?.queryTypes || ['semantic'];
  const resultSize = testConfig.parameters?.resultSize || 50;
  const searchComplexity = testConfig.parameters?.searchComplexity || 'medium';

  for (let i = 0; i < loadConfig.operations; i++) {
    const operationStart = performance.now();

    try {
      const queryType = queryTypes[i % queryTypes.length];

      // Simulate search processing time based on query type and complexity
      let processingTime: number;
      const complexityMultiplier =
        {
          low: 0.5,
          medium: 1.0,
          high: 2.0,
        }[searchComplexity] || 1.0;

      switch (queryType) {
        case 'semantic':
          processingTime = (20 + Math.random() * 30) * complexityMultiplier;
          break;
        case 'keyword':
          processingTime = (5 + Math.random() * 15) * complexityMultiplier;
          break;
        case 'hybrid':
          processingTime = (15 + Math.random() * 25) * complexityMultiplier;
          break;
        default:
          processingTime = (10 + Math.random() * 20) * complexityMultiplier;
      }

      // Simulate async search operation
      await new Promise((resolve) => setTimeout(resolve, processingTime));

      const operationEnd = performance.now();
      const duration = operationEnd - operationStart;

      results.operations.push({
        index: i,
        type: 'search',
        subType: queryType,
        duration,
        success: true,
        resultSize,
        complexity: searchComplexity,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      const operationEnd = performance.now();
      const duration = operationEnd - operationStart;

      results.operations.push({
        index: i,
        type: 'search',
        duration,
        success: false,
        error: error instanceof Error ? error.message : String(error),
        timestamp: new Date().toISOString(),
      });

      results.errors++;
    }

    // Add operation delay if specified
    if (loadConfig.operationDelay && loadConfig.operationDelay > 0) {
      await new Promise((resolve) => setTimeout(resolve, loadConfig.operationDelay));
    }
  }
}

/**
 * Execute circuit breaker scenario
 */
async function executeCircuitBreakerScenario(
  testConfig: any,
  loadConfig: LoadTestConfig,
  results: any
): Promise<void> {
  const failureRate = testConfig.parameters?.failureRate || 0.1;
  const threshold = testConfig.parameters?.threshold || 5;
  let circuitState = 'closed';
  let failureCount = 0;

  for (let i = 0; i < loadConfig.operations; i++) {
    const operationStart = performance.now();

    try {
      // Simulate circuit breaker logic
      const shouldFail = Math.random() < failureRate;
      let processingTime: number;

      if (circuitState === 'open') {
        // Fast fail when circuit is open
        processingTime = 1 + Math.random() * 2;
      } else if (shouldFail) {
        // Simulate failure
        processingTime = 5 + Math.random() * 10;
        failureCount++;
        if (failureCount >= threshold) {
          circuitState = 'open';
        }
        throw new Error('Simulated operation failure');
      } else {
        // Simulate success
        processingTime = 1 + Math.random() * 3;
        failureCount = Math.max(0, failureCount - 1);
        if (circuitState === 'open' && failureCount < threshold / 2) {
          circuitState = 'half-open';
        } else if (circuitState === 'half-open') {
          circuitState = 'closed';
        }
      }

      await new Promise((resolve) => setTimeout(resolve, processingTime));

      const operationEnd = performance.now();
      const duration = operationEnd - operationStart;

      results.operations.push({
        index: i,
        type: 'circuit_breaker',
        duration,
        success: true,
        circuitState,
        failureCount,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      const operationEnd = performance.now();
      const duration = operationEnd - operationStart;

      results.operations.push({
        index: i,
        type: 'circuit_breaker',
        duration,
        success: false,
        error: error instanceof Error ? error.message : String(error),
        circuitState,
        failureCount,
        timestamp: new Date().toISOString(),
      });

      results.errors++;
    }

    // Add operation delay if specified
    if (loadConfig.operationDelay && loadConfig.operationDelay > 0) {
      await new Promise((resolve) => setTimeout(resolve, loadConfig.operationDelay));
    }
  }
}

/**
 * Execute health check scenario
 */
async function executeHealthCheckScenario(
  testConfig: any,
  loadConfig: LoadTestConfig,
  results: any
): Promise<void> {
  const checkTypes = testConfig.parameters?.checkTypes || ['database'];
  const checkInterval = testConfig.parameters?.checkInterval || 1000;

  for (let i = 0; i < loadConfig.operations; i++) {
    const operationStart = performance.now();

    try {
      const checkType = checkTypes[i % checkTypes.length];

      // Simulate health check processing time based on check type
      let processingTime: number;
      switch (checkType) {
        case 'database':
          processingTime = 20 + Math.random() * 50;
          break;
        case 'memory':
          processingTime = 5 + Math.random() * 10;
          break;
        case 'circuit_breaker':
          processingTime = 1 + Math.random() * 5;
          break;
        case 'api':
          processingTime = 10 + Math.random() * 20;
          break;
        default:
          processingTime = 10 + Math.random() * 15;
      }

      await new Promise((resolve) => setTimeout(resolve, processingTime));

      const operationEnd = performance.now();
      const duration = operationEnd - operationStart;

      results.operations.push({
        index: i,
        type: 'health_check',
        subType: checkType,
        duration,
        success: true,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      const operationEnd = performance.now();
      const duration = operationEnd - operationStart;

      results.operations.push({
        index: i,
        type: 'health_check',
        duration,
        success: false,
        error: error instanceof Error ? error.message : String(error),
        timestamp: new Date().toISOString(),
      });

      results.errors++;
    }

    // Add check interval if specified
    if (checkInterval > 0) {
      await new Promise((resolve) => setTimeout(resolve, checkInterval));
    }
  }
}

/**
 * Execute generic scenario
 */
async function executeGenericScenario(
  testConfig: any,
  loadConfig: LoadTestConfig,
  results: any
): Promise<void> {
  for (let i = 0; i < loadConfig.operations; i++) {
    const operationStart = performance.now();

    try {
      // Generic operation simulation
      const processingTime = 10 + Math.random() * 30;
      await new Promise((resolve) => setTimeout(resolve, processingTime));

      const operationEnd = performance.now();
      const duration = operationEnd - operationStart;

      results.operations.push({
        index: i,
        type: 'generic',
        duration,
        success: true,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      const operationEnd = performance.now();
      const duration = operationEnd - operationStart;

      results.operations.push({
        index: i,
        type: 'generic',
        duration,
        success: false,
        error: error instanceof Error ? error.message : String(error),
        timestamp: new Date().toISOString(),
      });

      results.errors++;
    }

    // Add operation delay if specified
    if (loadConfig.operationDelay && loadConfig.operationDelay > 0) {
      await new Promise((resolve) => setTimeout(resolve, loadConfig.operationDelay));
    }
  }
}

/**
 * Calculate scenario metrics
 */
function calculateScenarioMetrics(results: any): void {
  const successfulOps = results.operations.filter((op: any) => op.success);
  const durations = successfulOps
    .map((op: any) => op.duration)
    .sort((a: number, b: number) => a - b);

  if (durations.length > 0) {
    // Calculate percentiles
    results.metrics.latencies.min = durations[0];
    results.metrics.latencies.max = durations[durations.length - 1];
    results.metrics.latencies.p50 = percentile(durations, 50);
    results.metrics.latencies.p95 = percentile(durations, 95);
    results.metrics.latencies.p99 = percentile(durations, 99);

    // Calculate throughput
    const totalTime = results.operations.reduce((sum: number, op: any) => sum + op.duration, 0);
    results.metrics.throughput = (successfulOps.length * 1000) / totalTime;

    // Calculate error rate
    results.metrics.errorRate = (results.errors / results.operations.length) * 100;
  }
}

/**
 * Calculate percentile
 */
function percentile(sortedArray: number[], p: number): number {
  if (sortedArray.length === 0) return 0;
  const index = (p / 100) * (sortedArray.length - 1);
  const lower = Math.floor(index);
  const upper = Math.ceil(index);
  if (lower === upper) return sortedArray[lower];
  const weight = index - lower;
  return sortedArray[lower] * (1 - weight) + sortedArray[upper] * weight;
}

/**
 * Get performance scenarios by category
 */
export function getPerformanceScenariosByCategory(category: string): BenchmarkScenario[] {
  const allScenarios = createPerformanceLoadScenarios();
  return allScenarios.filter((scenario) => scenario.tags?.includes(category));
}

/**
 * Get critical performance scenarios
 */
export function getCriticalPerformanceScenarios(): BenchmarkScenario[] {
  const allScenarios = createPerformanceLoadScenarios();
  return allScenarios.filter((scenario) => scenario.tags?.includes('critical'));
}

/**
 * Get performance scenarios by name pattern
 */
export function getPerformanceScenariosByName(pattern: string): BenchmarkScenario[] {
  const allScenarios = createPerformanceLoadScenarios();
  const regex = new RegExp(pattern, 'i');
  return allScenarios.filter(
    (scenario) => regex.test(scenario.name) || regex.test(scenario.description)
  );
}

// Export scenario collections for easy access
export const KnowledgeStorageScenarios = getPerformanceScenariosByCategory('storage');
export const SearchRetrievalScenarios = getPerformanceScenariosByCategory('search');
export const CircuitBreakerScenarios = getPerformanceScenariosByCategory('circuit_breaker');
export const HealthCheckScenarios = getPerformanceScenariosByCategory('health');
export const CriticalPerformanceScenarios = getCriticalPerformanceScenarios();
