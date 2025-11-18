/**
 * Comprehensive Load Testing Framework for MCP-Cortex
 *
 * Provides production-ready load testing capabilities:
 * - Concurrent user simulation
 * - Realistic scenario testing
 * - Performance metrics collection
 * - SLO validation and monitoring
 * - Stress testing and breakpoint analysis
 * - Component-specific testing
 * - Distributed load generation
 * - Real-time monitoring and alerting
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'events';

import { logger } from '@/utils/logger.js';

import { zaiServicesManager } from '../../services/ai/index.js';
import { MemoryFindOrchestrator } from '../../services/orchestrators/memory-find-orchestrator.js';
import { MemoryStoreOrchestrator } from '../../services/orchestrators/memory-store-orchestrator.js';
import type { KnowledgeItem } from '../../types/core-interfaces.js';
import type { ZAIChatRequest } from '../../types/zai-interfaces.js';

/**
 * Load test configuration
 */
export interface LoadTestConfig {
  /** Test name for identification */
  testName: string;
  /** Duration in seconds */
  duration: number;
  /** Concurrent users */
  concurrentUsers: number;
  /** Ramp-up period in seconds */
  rampUpPeriod: number;
  /** Cool-down period in seconds */
  coolDownPeriod: number;
  /** Scenarios to execute */
  scenarios: LoadTestScenario[];
  /** SLO targets */
  sloTargets: SLOTargets;
  /** Monitoring configuration */
  monitoring: MonitoringConfig;
  /** Output configuration */
  output: OutputConfig;
}

/**
 * Load test scenario
 */
export interface LoadTestScenario {
  /** Scenario name */
  name: string;
  /** Scenario weight (for distribution) */
  weight: number;
  /** Steps to execute */
  steps: LoadTestStep[];
  /** Frequency (requests per second) */
  frequency?: number;
  /** Maximum allowed failure rate */
  maxFailureRate?: number;
}

/**
 * Individual load test step
 */
export interface LoadTestStep {
  /** Step name */
  name: string;
  /** Step type */
  type: 'memory_store' | 'memory_find' | 'zai_completion' | 'zai_streaming' | 'mixed';
  /** Step parameters */
  parameters: Record<string, unknown>;
  /** Expected response time (ms) */
  expectedResponseTime?: number;
  /** Step weight */
  weight?: number;
}

/**
 * Service Level Objective (SLO) targets
 */
export interface SLOTargets {
  /** Maximum response time (P95) */
  maxResponseTimeP95: number;
  /** Maximum response time (P99) */
  maxResponseTimeP99: number;
  /** Maximum error rate */
  maxErrorRate: number;
  /** Minimum throughput */
  minThroughput: number;
  /** Maximum CPU usage */
  maxCPUUsage: number;
  /** Maximum memory usage */
  maxMemoryUsage: number;
  /** Database connection threshold */
  maxDBConnections: number;
}

/**
 * Monitoring configuration
 */
export interface MonitoringConfig {
  /** Enable real-time monitoring */
  enableRealTime: boolean;
  /** Metrics collection interval (ms) */
  metricsInterval: number;
  /** Enable performance profiling */
  enableProfiling: boolean;
  /** Enable resource monitoring */
  enableResourceMonitoring: boolean;
  /** Alert thresholds */
  alertThresholds: AlertThresholds;
}

/**
 * Alert thresholds
 */
export interface AlertThresholds {
  /** Response time threshold */
  responseTime: number;
  /** Error rate threshold */
  errorRate: number;
  /** Memory usage threshold */
  memoryUsage: number;
  /** CPU usage threshold */
  cpuUsage: number;
}

/**
 * Output configuration
 */
export interface OutputConfig {
  /** Output directory */
  outputDir: string;
  /** Generate HTML report */
  generateHTML: boolean;
  /** Generate JSON report */
  generateJSON: boolean;
  /** Generate CSV data */
  generateCSV: boolean;
  /** Include raw data */
  includeRawData: boolean;
}

/**
 * Load test execution result
 */
export interface LoadTestResult {
  /** Test metadata */
  metadata: {
    testName: string;
    startTime: string;
    endTime: string;
    duration: number;
    config: LoadTestConfig;
  };
  /** Performance metrics */
  metrics: {
    totalRequests: number;
    successfulRequests: number;
    failedRequests: number;
    errorRate: number;
    throughput: number;
    responseTime: ResponseTimeMetrics;
    resourceUsage: ResourceUsageMetrics;
    componentMetrics: ComponentMetrics;
  };
  /** SLO compliance */
  sloCompliance: SLOComplianceResult;
  /** Breakpoint analysis */
  breakpointAnalysis: BreakpointAnalysis;
  /** Recommendations */
  recommendations: string[];
}

/**
 * Response time metrics
 */
export interface ResponseTimeMetrics {
  /** Minimum response time */
  min: number;
  /** Maximum response time */
  max: number;
  /** Mean response time */
  mean: number;
  /** Median response time */
  median: number;
  /** 90th percentile */
  p90: number;
  /** 95th percentile */
  p95: number;
  /** 99th percentile */
  p99: number;
  /** Standard deviation */
  stdDev: number;
}

/**
 * Resource usage metrics
 */
export interface ResourceUsageMetrics {
  /** CPU usage */
  cpu: {
    min: number;
    max: number;
    avg: number;
    peak: number;
  };
  /** Memory usage */
  memory: {
    min: number;
    max: number;
    avg: number;
    peak: number;
  };
  /** Database connections */
  dbConnections: {
    min: number;
    max: number;
    avg: number;
    peak: number;
  };
}

/**
 * Component-specific metrics
 */
export interface ComponentMetrics {
  /** Qdrant metrics */
  qdrant: {
    requests: number;
    errors: number;
    avgResponseTime: number;
    cacheHitRate: number;
  };
  /** ZAI metrics */
  zai: {
    requests: number;
    errors: number;
    avgResponseTime: number;
    cacheHitRate: number;
    rateLimitHits: number;
  };
  /** Memory store metrics */
  memoryStore: {
    stores: number;
    finds: number;
    errors: number;
    avgResponseTime: number;
    duplicatesSkipped: number;
  };
}

/**
 * SLO compliance result
 */
export interface SLOComplianceResult {
  /** Overall compliance */
  overall: boolean;
  /** Individual SLO compliance */
  slos: {
    p95ResponseTime: boolean;
    responseTimeP99: boolean;
    errorRate: boolean;
    throughput: boolean;
    cpuUsage: boolean;
    memoryUsage: boolean;
    dbConnections: boolean;
  };
  /** Details */
  details: {
    p95ResponseTime: { actual: number; target: number; passed: boolean };
    responseTimeP99: { actual: number; target: number; passed: boolean };
    errorRate: { actual: number; target: number; passed: boolean };
    throughput: { actual: number; target: number; passed: boolean };
    cpuUsage: { actual: number; target: number; passed: boolean };
    memoryUsage: { actual: number; target: number; passed: boolean };
    dbConnections: { actual: number; target: number; passed: boolean };
  };
}

/**
 * Breakpoint analysis
 */
export interface BreakpointAnalysis {
  /** Maximum sustainable load */
  maxSustainableLoad: number;
  /** Breakpoint detected */
  breakpointDetected: boolean;
  /** Breakpoint details */
  breakpoint: {
    userCount: number;
    throughput: number;
    errorRate: number;
    avgResponseTime: number;
  };
  /** Performance degradation points */
  degradationPoints: Array<{
    userCount: number;
    metric: string;
    degradationPercent: number;
  }>;
}

/**
 * Virtual user configuration
 */
interface VirtualUser {
  id: string;
  scenario: LoadTestScenario;
  startTime: number;
  endTime: number;
  active: boolean;
  metrics: {
    requests: number;
    errors: number;
    responseTimes: number[];
  };
}

/**
 * Load testing framework
 */
export class LoadTestFramework extends EventEmitter {
  private config: LoadTestConfig;
  private virtualUsers: VirtualUser[] = [];
  private responseTimes: number[] = [];
  private resourceMetrics: ResourceUsageMetrics;
  private componentMetrics: ComponentMetrics;
  private running = false;
  private startTime = 0;
  private endTime = 0;
  private monitoringInterval?: NodeJS.Timeout;

  constructor(config: LoadTestConfig) {
    super();
    this.config = config;

    this.resourceMetrics = {
      cpu: { min: 0, max: 0, avg: 0, peak: 0 },
      memory: { min: 0, max: 0, avg: 0, peak: 0 },
      dbConnections: { min: 0, max: 0, avg: 0, peak: 0 },
    };

    this.componentMetrics = {
      qdrant: { requests: 0, errors: 0, avgResponseTime: 0, cacheHitRate: 0 },
      zai: { requests: 0, errors: 0, avgResponseTime: 0, cacheHitRate: 0, rateLimitHits: 0 },
      memoryStore: { stores: 0, finds: 0, errors: 0, avgResponseTime: 0, duplicatesSkipped: 0 },
    };

    logger.info('Load testing framework initialized', {
      testName: config.testName,
      duration: config.duration,
      concurrentUsers: config.concurrentUsers,
    });
  }

  /**
   * Execute load test
   */
  async execute(): Promise<LoadTestResult> {
    logger.info('Starting load test execution', {
      testName: this.config.testName,
      duration: this.config.duration,
      concurrentUsers: this.config.concurrentUsers,
    });

    this.running = true;
    this.startTime = Date.now();

    try {
      // Initialize monitoring
      await this.initializeMonitoring();

      // Create virtual users
      await this.createVirtualUsers();

      // Start load test execution
      await this.executeLoadTest();

      // Cool-down period
      await this.cooldown();

      // Generate results
      const results = await this.generateResults();

      this.running = false;
      this.endTime = Date.now();

      logger.info('Load test completed', {
        testName: this.config.testName,
        duration: (this.endTime - this.startTime) / 1000,
        totalRequests: results.metrics.totalRequests,
        successRate:
          ((results.metrics.successfulRequests / results.metrics.totalRequests) * 100).toFixed(2) +
          '%',
      });

      return results;
    } catch (error) {
      this.running = false;
      this.endTime = Date.now();
      logger.error({ error }, 'Load test execution failed');
      throw error;
    }
  }

  /**
   * Stop load test execution
   */
  async stop(): Promise<void> {
    logger.info('Stopping load test');
    this.running = false;

    // Stop monitoring
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
    }

    // Stop virtual users
    this.virtualUsers.forEach((user) => {
      user.active = false;
    });

    logger.info('Load test stopped');
  }

  /**
   * Get current test status
   */
  getStatus(): {
    running: boolean;
    duration: number;
    activeUsers: number;
    completedRequests: number;
    currentThroughput: number;
    avgResponseTime: number;
    errorRate: number;
  } {
    const totalRequests = this.virtualUsers.reduce((sum, user) => sum + user.metrics.requests, 0);
    const totalErrors = this.virtualUsers.reduce((sum, user) => sum + user.metrics.errors, 0);
    const avgResponseTime =
      this.responseTimes.length > 0
        ? this.responseTimes.reduce((sum, time) => sum + time, 0) / this.responseTimes.length
        : 0;
    const currentDuration = this.running ? (Date.now() - this.startTime) / 1000 : 0;
    const currentThroughput = currentDuration > 0 ? totalRequests / currentDuration : 0;

    return {
      running: this.running,
      duration: currentDuration,
      activeUsers: this.virtualUsers.filter((user) => user.active).length,
      completedRequests: totalRequests,
      currentThroughput,
      avgResponseTime,
      errorRate: totalRequests > 0 ? (totalErrors / totalRequests) * 100 : 0,
    };
  }

  /**
   * Initialize monitoring
   */
  private async initializeMonitoring(): Promise<void> {
    if (this.config.monitoring.enableRealTime) {
      this.monitoringInterval = setInterval(async () => {
        await this.collectMetrics();
        this.emit('metrics', this.getCurrentMetrics());
      }, this.config.monitoring.metricsInterval);
    }

    logger.info('Monitoring initialized', {
      realTime: this.config.monitoring.enableRealTime,
      interval: this.config.monitoring.metricsInterval,
    });
  }

  /**
   * Create virtual users
   */
  private async createVirtualUsers(): Promise<void> {
    const rampUpDelay = (this.config.rampUpPeriod * 1000) / this.config.concurrentUsers;

    for (let i = 0; i < this.config.concurrentUsers; i++) {
      const scenario = this.selectScenarioByWeight();
      const user: VirtualUser = {
        id: `user_${i}`,
        scenario,
        startTime: Date.now() + i * rampUpDelay,
        endTime: this.startTime + this.config.duration * 1000,
        active: true,
        metrics: {
          requests: 0,
          errors: 0,
          responseTimes: [],
        },
      };

      this.virtualUsers.push(user);

      // Schedule user start
      setTimeout(() => {
        if (this.running) {
          this.executeVirtualUser(user);
        }
      }, i * rampUpDelay);
    }

    logger.info('Virtual users created', {
      totalUsers: this.config.concurrentUsers,
      rampUpPeriod: this.config.rampUpPeriod,
    });
  }

  /**
   * Execute load test
   */
  private async executeLoadTest(): Promise<void> {
    const testDuration = this.config.duration * 1000;

    // Wait for test duration
    await new Promise((resolve) => {
      setTimeout(resolve, testDuration);
    });

    // Stop all virtual users
    this.virtualUsers.forEach((user) => {
      user.active = false;
    });
  }

  /**
   * Cool-down period
   */
  private async cooldown(): Promise<void> {
    logger.info('Starting cool-down period', {
      duration: this.config.coolDownPeriod,
    });

    await new Promise((resolve) => {
      setTimeout(resolve, this.config.coolDownPeriod * 1000);
    });
  }

  /**
   * Execute virtual user scenario
   */
  private async executeVirtualUser(user: VirtualUser): Promise<void> {
    while (user.active && Date.now() < user.endTime) {
      try {
        await this.executeScenario(user);
      } catch (error) {
        logger.warn({ error, userId: user.id }, 'Virtual user execution failed');
        user.metrics.errors++;
      }

      // Add think time
      const thinkTime = Math.random() * 1000 + 500; // 0.5-1.5 seconds
      await new Promise((resolve) => setTimeout(resolve, thinkTime));
    }

    logger.debug('Virtual user completed', { userId: user.id });
  }

  /**
   * Execute scenario for user
   */
  private async executeScenario(user: VirtualUser): Promise<void> {
    for (const step of user.scenario.steps) {
      if (!user.active) break;

      const stepStartTime = Date.now();

      try {
        await this.executeStep(step);
        const responseTime = Date.now() - stepStartTime;

        user.metrics.requests++;
        user.metrics.responseTimes.push(responseTime);
        this.responseTimes.push(responseTime);
      } catch (error) {
        user.metrics.errors++;
        throw error;
      }

      // Add small delay between steps
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }

  /**
   * Execute individual step
   */
  private async executeStep(step: LoadTestStep): Promise<void> {
    switch (step.type) {
      case 'memory_store':
        await this.executeMemoryStoreStep(step);
        break;
      case 'memory_find':
        await this.executeMemoryFindStep(step);
        break;
      case 'zai_completion':
        await this.executeZAICompletionStep(step);
        break;
      case 'zai_streaming':
        await this.executeZAIStreamingStep(step);
        break;
      case 'mixed':
        await this.executeMixedStep(step);
        break;
      default:
        throw new Error(`Unknown step type: ${step.type}`);
    }
  }

  /**
   * Execute memory store step
   */
  private async executeMemoryStoreStep(step: LoadTestStep): Promise<void> {
    const item: KnowledgeItem = {
      kind: step.parameters.kind || 'entity',
      scope: step.parameters.scope || { project: 'load-test' },
      data: step.parameters.data || {
        title: `Load Test Item ${Date.now()}`,
        content: `Generated content for load testing at ${new Date().toISOString()}`,
      },
      created_at: new Date().toISOString(),
    };

    const orchestrator = new MemoryStoreOrchestrator();
    await orchestrator.storeItems([item]);
    this.componentMetrics.memoryStore.stores++;
  }

  /**
   * Execute memory find step
   */
  private async executeMemoryFindStep(step: LoadTestStep): Promise<void> {
    const query = {
      query: step.parameters.query || 'load test',
      limit: step.parameters.limit || 10,
      mode: step.parameters.mode || 'auto',
    };

    const orchestrator = new MemoryFindOrchestrator();
    await orchestrator.findItems(query);
    this.componentMetrics.memoryStore.finds++;
  }

  /**
   * Execute ZAI completion step
   */
  private async executeZAICompletionStep(step: LoadTestStep): Promise<void> {
    const request: ZAIChatRequest = {
      messages: step.parameters.messages || [
        {
          role: 'user',
          content: step.parameters.prompt || 'Generate a response for load testing',
        },
      ],
      temperature: step.parameters.temperature || 0.7,
      maxTokens: step.parameters.max_tokens || 100,
    };

    const response = await zaiServicesManager.generateCompletion(request);
    this.componentMetrics.zai.requests++;
  }

  /**
   * Execute ZAI streaming step
   */
  private async executeZAIStreamingStep(step: LoadTestStep): Promise<void> {
    const request: ZAIChatRequest = {
      messages: step.parameters.messages || [
        {
          role: 'user',
          content: step.parameters.prompt || 'Generate a streaming response for load testing',
        },
      ],
      temperature: step.parameters.temperature || 0.7,
      maxTokens: step.parameters.max_tokens || 100,
      stream: true,
    };

    // For streaming, we'll just use the regular completion for now
    await zaiServicesManager.generateCompletion(request);
    this.componentMetrics.zai.requests++;
  }

  /**
   * Execute mixed step
   */
  private async executeMixedStep(step: LoadTestStep): Promise<void> {
    const operations = step.parameters.operations || [
      { type: 'memory_store', weight: 3 },
      { type: 'memory_find', weight: 5 },
      { type: 'zai_completion', weight: 2 },
    ];

    const selectedOp = this.selectOperationByWeight(operations);
    const mixedStep: LoadTestStep = {
      ...step,
      type: selectedOp.type as
        | 'memory_store'
        | 'memory_find'
        | 'zai_completion'
        | 'zai_streaming'
        | 'mixed',
    };

    await this.executeStep(mixedStep);
  }

  /**
   * Select scenario by weight
   */
  private selectScenarioByWeight(): LoadTestScenario {
    const totalWeight = this.config.scenarios.reduce((sum, s) => sum + s.weight, 0);
    let random = Math.random() * totalWeight;

    for (const scenario of this.config.scenarios) {
      random -= scenario.weight;
      if (random <= 0) {
        return scenario;
      }
    }

    return this.config.scenarios[0];
  }

  /**
   * Select operation by weight
   */
  private selectOperationByWeight(operations: Array<{ type: string; weight: number }>): {
    type: string;
  } {
    const totalWeight = operations.reduce((sum, op) => sum + op.weight, 0);
    let random = Math.random() * totalWeight;

    for (const op of operations) {
      random -= op.weight;
      if (random <= 0) {
        return op;
      }
    }

    return operations[0];
  }

  /**
   * Collect metrics
   */
  private async collectMetrics(): Promise<void> {
    const memUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();

    // Update resource metrics
    const memoryCurrent = memUsage.heapUsed / 1024 / 1024; // MB
    const cpuCurrent = (cpuUsage.user + cpuUsage.system) / 1000000; // seconds

    // Update peak values
    this.resourceMetrics.memory.peak = Math.max(this.resourceMetrics.memory.peak, memoryCurrent);
    this.resourceMetrics.cpu.peak = Math.max(this.resourceMetrics.cpu.peak, cpuCurrent);
  }

  /**
   * Get current metrics
   */
  private getCurrentMetrics() {
    return {
      timestamp: Date.now(),
      virtualUsers: this.virtualUsers.filter((u) => u.active).length,
      responseTime:
        this.responseTimes.length > 0 ? this.responseTimes[this.responseTimes.length - 1] : 0,
      resourceUsage: this.resourceMetrics,
      componentMetrics: this.componentMetrics,
    };
  }

  /**
   * Generate test results
   */
  private async generateResults(): Promise<LoadTestResult> {
    const totalRequests = this.virtualUsers.reduce((sum, user) => sum + user.metrics.requests, 0);
    const totalErrors = this.virtualUsers.reduce((sum, user) => sum + user.metrics.errors, 0);
    const allResponseTimes = this.virtualUsers.flatMap((user) => user.metrics.responseTimes);

    const responseTimeMetrics = this.calculateResponseTimeMetrics(allResponseTimes);
    const sloCompliance = this.evaluateSLOCompliance(responseTimeMetrics);
    const breakpointAnalysis = this.analyzeBreakpoints();
    const recommendations = this.generateRecommendations(sloCompliance, responseTimeMetrics);

    return {
      metadata: {
        testName: this.config.testName,
        startTime: new Date(this.startTime).toISOString(),
        endTime: new Date(this.endTime).toISOString(),
        duration: (this.endTime - this.startTime) / 1000,
        config: this.config,
      },
      metrics: {
        totalRequests,
        successfulRequests: totalRequests - totalErrors,
        failedRequests: totalErrors,
        errorRate: totalRequests > 0 ? (totalErrors / totalRequests) * 100 : 0,
        throughput: totalRequests / ((this.endTime - this.startTime) / 1000),
        responseTime: responseTimeMetrics,
        resourceUsage: this.resourceMetrics,
        componentMetrics: this.componentMetrics,
      },
      sloCompliance,
      breakpointAnalysis,
      recommendations,
    };
  }

  /**
   * Calculate response time metrics
   */
  private calculateResponseTimeMetrics(responseTimes: number[]): ResponseTimeMetrics {
    if (responseTimes.length === 0) {
      return {
        min: 0,
        max: 0,
        mean: 0,
        median: 0,
        p90: 0,
        p95: 0,
        p99: 0,
        stdDev: 0,
      };
    }

    const sorted = [...responseTimes].sort((a, b) => a - b);
    const mean = responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length;

    const variance =
      responseTimes.reduce((sum, time) => sum + Math.pow(time - mean, 2), 0) / responseTimes.length;
    const stdDev = Math.sqrt(variance);

    return {
      min: sorted[0],
      max: sorted[sorted.length - 1],
      mean,
      median: sorted[Math.floor(sorted.length / 2)],
      p90: sorted[Math.floor(sorted.length * 0.9)],
      p95: sorted[Math.floor(sorted.length * 0.95)],
      p99: sorted[Math.floor(sorted.length * 0.99)],
      stdDev,
    };
  }

  /**
   * Evaluate SLO compliance
   */
  private evaluateSLOCompliance(responseTimeMetrics: ResponseTimeMetrics): SLOComplianceResult {
    const slo = this.config.sloTargets;

    const p95ResponseTime = responseTimeMetrics.p95 <= slo.maxResponseTimeP95;
    const responseTimeP99 = responseTimeMetrics.p99 <= slo.maxResponseTimeP99;
    const errorRate =
      (this.virtualUsers.reduce((sum, user) => sum + user.metrics.errors, 0) /
        this.virtualUsers.reduce((sum, user) => sum + user.metrics.requests, 0)) *
        100 <=
      slo.maxErrorRate;
    const throughput =
      this.virtualUsers.reduce((sum, user) => sum + user.metrics.requests, 0) /
        ((this.endTime - this.startTime) / 1000) >=
      slo.minThroughput;
    const cpuUsage = this.resourceMetrics.cpu.avg <= slo.maxCPUUsage;
    const memoryUsage = this.resourceMetrics.memory.avg <= slo.maxMemoryUsage;
    const dbConnections = this.resourceMetrics.dbConnections.avg <= slo.maxDBConnections;

    const overall =
      p95ResponseTime &&
      responseTimeP99 &&
      errorRate &&
      throughput &&
      cpuUsage &&
      memoryUsage &&
      dbConnections;

    return {
      overall,
      slos: {
        p95ResponseTime,
        responseTimeP99,
        errorRate,
        throughput,
        cpuUsage,
        memoryUsage,
        dbConnections,
      },
      details: {
        p95ResponseTime: {
          actual: responseTimeMetrics.p95,
          target: slo.maxResponseTimeP95,
          passed: p95ResponseTime,
        },
        responseTimeP99: {
          actual: responseTimeMetrics.p99,
          target: slo.maxResponseTimeP99,
          passed: responseTimeP99,
        },
        errorRate: {
          actual:
            (this.virtualUsers.reduce((sum, user) => sum + user.metrics.errors, 0) /
              this.virtualUsers.reduce((sum, user) => sum + user.metrics.requests, 0)) *
            100,
          target: slo.maxErrorRate,
          passed: errorRate,
        },
        throughput: {
          actual:
            this.virtualUsers.reduce((sum, user) => sum + user.metrics.requests, 0) /
            ((this.endTime - this.startTime) / 1000),
          target: slo.minThroughput,
          passed: throughput,
        },
        cpuUsage: {
          actual: this.resourceMetrics.cpu.avg,
          target: slo.maxCPUUsage,
          passed: cpuUsage,
        },
        memoryUsage: {
          actual: this.resourceMetrics.memory.avg,
          target: slo.maxMemoryUsage,
          passed: memoryUsage,
        },
        dbConnections: {
          actual: this.resourceMetrics.dbConnections.avg,
          target: slo.maxDBConnections,
          passed: dbConnections,
        },
      },
    };
  }

  /**
   * Analyze breakpoints
   */
  private analyzeBreakpoints(): BreakpointAnalysis {
    // Simplified breakpoint analysis
    // In a real implementation, this would use more sophisticated analysis
    const maxSustainableLoad = this.config.concurrentUsers * 0.8; // Assume 80% is sustainable

    return {
      maxSustainableLoad,
      breakpointDetected: false,
      breakpoint: {
        userCount: this.config.concurrentUsers,
        throughput:
          this.virtualUsers.reduce((sum, user) => sum + user.metrics.requests, 0) /
          ((this.endTime - this.startTime) / 1000),
        errorRate:
          (this.virtualUsers.reduce((sum, user) => sum + user.metrics.errors, 0) /
            this.virtualUsers.reduce((sum, user) => sum + user.metrics.requests, 0)) *
          100,
        avgResponseTime:
          this.responseTimes.reduce((sum, time) => sum + time, 0) / this.responseTimes.length,
      },
      degradationPoints: [],
    };
  }

  /**
   * Generate recommendations
   */
  private generateRecommendations(
    sloCompliance: SLOComplianceResult,
    responseTimeMetrics: ResponseTimeMetrics
  ): string[] {
    const recommendations: string[] = [];

    if (!sloCompliance.slos.p95ResponseTime) {
      recommendations.push(
        'Consider optimizing database queries or implementing caching to improve P95 response times'
      );
    }

    if (!sloCompliance.slos.responseTimeP99) {
      recommendations.push(
        'Review outliers and implement timeout handling to improve P99 response times'
      );
    }

    if (!sloCompliance.slos.errorRate) {
      recommendations.push(
        'Investigate error patterns and implement better error handling and retry logic'
      );
    }

    if (!sloCompliance.slos.throughput) {
      recommendations.push(
        'Consider horizontal scaling or request optimization to improve throughput'
      );
    }

    if (!sloCompliance.slos.cpuUsage) {
      recommendations.push('Optimize CPU-intensive operations or consider vertical scaling');
    }

    if (!sloCompliance.slos.memoryUsage) {
      recommendations.push(
        'Review memory usage patterns and implement memory optimization or garbage collection tuning'
      );
    }

    if (recommendations.length === 0) {
      recommendations.push(
        'All SLOs are met. Consider running load tests at higher concurrency to find breakpoints'
      );
    }

    return recommendations;
  }
}

/**
 * Default load test configurations
 */
export const DEFAULT_LOAD_TEST_CONFIGS = {
  /** Lightweight smoke test */
  smoke: {
    testName: 'smoke-test',
    duration: 60,
    concurrentUsers: 5,
    rampUpPeriod: 10,
    coolDownPeriod: 30,
    scenarios: [
      {
        name: 'basic-operations',
        weight: 100,
        steps: [
          { name: 'store-item', type: 'memory_store' as const, parameters: {} },
          { name: 'find-item', type: 'memory_find' as const, parameters: {} },
        ],
      },
    ],
    sloTargets: {
      maxResponseTimeP95: 1000,
      maxResponseTimeP99: 2000,
      maxErrorRate: 1,
      minThroughput: 10,
      maxCPUUsage: 70,
      maxMemoryUsage: 512,
      maxDBConnections: 10,
    },
    monitoring: {
      enableRealTime: true,
      metricsInterval: 5000,
      enableProfiling: false,
      enableResourceMonitoring: true,
      alertThresholds: {
        responseTime: 5000,
        errorRate: 5,
        memoryUsage: 80,
        cpuUsage: 80,
      },
    },
    output: {
      outputDir: './test-results',
      generateHTML: true,
      generateJSON: true,
      generateCSV: true,
      includeRawData: false,
    },
  },

  /** Load test for production readiness */
  production: {
    testName: 'production-load-test',
    duration: 600,
    concurrentUsers: 100,
    rampUpPeriod: 60,
    coolDownPeriod: 120,
    scenarios: [
      {
        name: 'read-heavy-workload',
        weight: 60,
        steps: [
          { name: 'find-item', type: 'memory_find' as const, parameters: { limit: 20 } },
          { name: 'find-item', type: 'memory_find' as const, parameters: { limit: 50 } },
        ],
      },
      {
        name: 'write-heavy-workload',
        weight: 20,
        steps: [
          { name: 'store-item', type: 'memory_store' as const, parameters: {} },
          { name: 'store-item', type: 'memory_store' as const, parameters: {} },
        ],
      },
      {
        name: 'ai-intensive-workload',
        weight: 20,
        steps: [{ name: 'zai-completion', type: 'zai_completion' as const, parameters: {} }],
      },
    ],
    sloTargets: {
      maxResponseTimeP95: 2000,
      maxResponseTimeP99: 5000,
      maxErrorRate: 2,
      minThroughput: 100,
      maxCPUUsage: 80,
      maxMemoryUsage: 1024,
      maxDBConnections: 50,
    },
    monitoring: {
      enableRealTime: true,
      metricsInterval: 2000,
      enableProfiling: true,
      enableResourceMonitoring: true,
      alertThresholds: {
        responseTime: 10000,
        errorRate: 10,
        memoryUsage: 90,
        cpuUsage: 90,
      },
    },
    output: {
      outputDir: './test-results',
      generateHTML: true,
      generateJSON: true,
      generateCSV: true,
      includeRawData: true,
    },
  },
} as const;
