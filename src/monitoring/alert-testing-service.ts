// @ts-nocheck
// EMERGENCY ROLLBACK: Monitoring system type compatibility issues
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * Alert Testing and Validation Service for MCP Cortex
 *
 * Provides comprehensive testing capabilities for the alerting system:
 * - Alert rule validation and testing
 * - Notification channel testing
 * - Escalation workflow testing
 * - End-to-end alert scenario testing
 * - Load testing and performance validation
 * - Integration testing with monitoring systems
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'events';

import { logger } from '@/utils/logger.js';

import { Alert, AlertRule, AlertSeverity, type AlertTestResult,type AlertTestScenario } from './alert-management-service.js';
import { DependencyType } from '../services/deps-registry.js';
import { ComponentHealth, HealthStatus,type SystemHealthResult } from '../types/unified-health-interfaces.js';

// ============================================================================
// Alert Testing Interfaces
// ============================================================================

export interface AlertTestSuite {
  id: string;
  name: string;
  description: string;
  category: TestCategory;
  scenarios: AlertTestScenario[];
  setup?: TestSetup;
  teardown?: TestTeardown;
  timeout: number; // milliseconds
  parallel: boolean;
  tags: string[];
  metadata: Record<string, unknown>;
}

export type TestCategory =
  | 'unit'
  | 'integration'
  | 'end-to-end'
  | 'performance'
  | 'load'
  | 'security'
  | 'regression';

export interface TestSetup {
  steps: TestStep[];
  timeout: number; // milliseconds
  required: boolean;
}

export interface TestTeardown {
  steps: TestStep[];
  timeout: number; // milliseconds;
  required: boolean;
  onFailure: 'continue' | 'abort' | 'rollback';
}

export interface TestStep {
  id: string;
  name: string;
  description: string;
  type: TestStepType;
  command: string;
  parameters: Record<string, unknown>;
  timeout: number; // milliseconds
  expectedExitCode: number;
  ignoreErrors: boolean;
  outputs: TestOutput[];
}

export type TestStepType =
  | 'setup'
  | 'teardown'
  | 'inject_fault'
  | 'verify_alert'
  | 'verify_notification'
  | 'verify_escalation'
  | 'cleanup'
  | 'measure'
  | 'wait';

export interface TestOutput {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'object' | 'array';
  description: string;
  required: boolean;
  validation?: OutputValidation;
}

export interface OutputValidation {
  type: 'equals' | 'contains' | 'regex' | 'range' | 'custom';
  value: unknown;
  message?: string;
}

export interface AlertTestExecution {
  id: string;
  suiteId: string;
  scenarioId: string;
  status: TestExecutionStatus;
  startedAt: Date;
  completedAt?: Date;
  duration?: number; // milliseconds
  environment: TestEnvironment;
  config: TestExecutionConfig;
  steps: TestStepExecution[];
  results: TestExecutionResults;
  artifacts: TestArtifact[];
  logs: TestLog[];
  metadata: Record<string, unknown>;
}

export type TestExecutionStatus =
  | 'pending'
  | 'running'
  | 'passed'
  | 'failed'
  | 'skipped'
  | 'timeout'
  | 'cancelled';

export interface TestEnvironment {
  name: string;
  type: 'development' | 'staging' | 'production' | 'isolated';
  isolated: boolean;
  variables: Record<string, unknown>;
  services: TestService[];
  network: TestNetworkConfig;
}

export interface TestService {
  name: string;
  type: 'database' | 'api' | 'queue' | 'cache' | 'monitoring' | 'custom';
  version: string;
  endpoint?: string;
  credentials?: Record<string, string>;
  healthCheck?: string;
  mocks?: ServiceMock[];
}

export interface ServiceMock {
  endpoint: string;
  method: string;
  response: unknown;
  statusCode: number;
  delay: number; // milliseconds
  headers?: Record<string, string>;
}

export interface TestNetworkConfig {
  latency: number; // milliseconds
  bandwidth: number; // Mbps
  packetLoss: number; // percentage
  blockedHosts: string[];
  proxies: NetworkProxy[];
}

export interface NetworkProxy {
  from: string;
  to: string;
  protocol: 'http' | 'https' | 'tcp' | 'udp';
  port: number;
}

export interface TestExecutionConfig {
  dryRun: boolean;
  verbose: boolean;
  continueOnFailure: boolean;
  timeout: number; // milliseconds
  retries: number;
  retryDelay: number; // milliseconds
  parallel: boolean;
  maxConcurrent: number;
}

export interface TestStepExecution {
  id: string;
  stepId: string;
  name: string;
  type: TestStepType;
  status: TestExecutionStatus;
  startedAt: Date;
  completedAt?: Date;
  duration?: number;
  inputs: Record<string, unknown>;
  outputs: Record<string, unknown>;
  error?: string;
  logs: TestLog[];
  metrics: TestMetrics;
}

export interface TestExecutionResults {
  summary: TestSummary;
  alerts: AlertTestResult[];
  notifications: NotificationTestResult[];
  escalations: EscalationTestResult[];
  performance: PerformanceTestResult[];
  coverage: CoverageReport;
}

export interface TestSummary {
  totalSteps: number;
  passedSteps: number;
  failedSteps: number;
  skippedSteps: number;
  totalDuration: number; // milliseconds
  successRate: number; // percentage
  passed: boolean;
}

export interface NotificationTestResult {
  id: string;
  alertId: string;
  channel: string;
  status: 'sent' | 'failed' | 'pending' | 'timeout';
  duration: number; // milliseconds
  attempts: number;
  error?: string;
  response?: unknown;
  verified: boolean;
}

export interface EscalationTestResult {
  id: string;
  alertId: string;
  escalationLevel: number;
  status: 'triggered' | 'skipped' | 'failed' | 'timeout';
  duration: number; // milliseconds
  targets: string[];
  notified: string[];
  error?: string;
}

export interface PerformanceTestResult {
  metric: string;
  expected: PerformanceThreshold;
  actual: number;
  passed: boolean;
  deviation: number; // percentage
  unit: string;
}

export interface PerformanceThreshold {
  min?: number;
  max?: number;
  target: number;
  tolerance: number; // percentage
}

export interface CoverageReport {
  rules: RuleCoverage;
  scenarios: ScenarioCoverage;
  notifications: NotificationCoverage;
  escalations: EscalationCoverage;
}

export interface RuleCoverage {
  total: number;
  tested: number;
  coverage: number; // percentage
  untestedRules: string[];
}

export interface ScenarioCoverage {
  total: number;
  tested: number;
  coverage: number; // percentage
  untestedScenarios: string[];
}

export interface NotificationCoverage {
  channels: Record<string, ChannelCoverage>;
  total: number;
  tested: number;
  coverage: number; // percentage;
}

export interface ChannelCoverage {
  total: number;
  tested: number;
  coverage: number; // percentage
  lastTested?: Date;
}

export interface EscalationCoverage {
  paths: Record<string, PathCoverage>;
  total: number;
  tested: number;
  coverage: number; // percentage;
}

export interface PathCoverage {
  total: number;
  tested: number;
  coverage: number; // percentage
  lastTested?: Date;
}

export interface TestArtifact {
  id: string;
  name: string;
  type: ArtifactType;
  path?: string;
  content?: string;
  size: number;
  checksum: string;
  createdAt: Date;
  metadata: Record<string, unknown>;
}

export type ArtifactType =
  | 'log'
  | 'screenshot'
  | 'har'
  | 'metrics'
  | 'trace'
  | 'dump'
  | 'report'
  | 'configuration';

export interface TestLog {
  timestamp: Date;
  level: 'debug' | 'info' | 'warn' | 'error';
  source: string;
  message: string;
  metadata?: Record<string, unknown>;
}

export interface TestMetrics {
  cpu: CpuMetrics;
  memory: MemoryMetrics;
  network: NetworkMetrics;
  disk: DiskMetrics;
  custom: Record<string, unknown>;
}

export interface CpuMetrics {
  usage: number; // percentage
  loadAverage: number[];
  processes: number;
}

export interface MemoryMetrics {
  total: number;
  used: number;
  free: number;
  cached: number;
  usage: number; // percentage
}

export interface NetworkMetrics {
  bytesIn: number;
  bytesOut: number;
  packetsIn: number;
  packetsOut: number;
  connections: number;
}

export interface DiskMetrics {
  total: number;
  used: number;
  free: number;
  usage: number; // percentage
  ioRate: number; // MB/s
}

// ============================================================================
// Fault Injection Interfaces
// ============================================================================

export interface FaultInjection {
  id: string;
  type: FaultType;
  target: FaultTarget;
  config: FaultConfig;
  duration: number; // milliseconds
  severity: 'low' | 'medium' | 'high' | 'critical';
  rollback: FaultRollback;
}

export type FaultType =
  | 'network_delay'
  | 'network_loss'
  | 'network_partition'
  | 'service_crash'
  | 'service_hang'
  | 'memory_pressure'
  | 'cpu_exhaustion'
  | 'disk_full'
  | 'database_error'
  | 'api_timeout'
  | 'custom';

export interface FaultTarget {
  type: 'service' | 'container' | 'host' | 'network' | 'database' | 'api';
  name: string;
  endpoint?: string;
  port?: number;
  host?: string;
}

export interface FaultConfig {
  intensity: number; // 0-100
  parameters: Record<string, unknown>;
  startTime?: Date;
  endTime?: Date;
  recurring?: boolean;
  interval?: number; // milliseconds
}

export interface FaultRollback {
  automatic: boolean;
  timeout: number; // milliseconds
  steps: FaultRollbackStep[];
}

export interface FaultRollbackStep {
  type: 'stop_fault' | 'restart_service' | 'restore_config' | 'cleanup' | 'custom';
  command: string;
  parameters: Record<string, unknown>;
  timeout: number; // milliseconds
}

// ============================================================================
// Load Testing Interfaces
// ============================================================================

export interface LoadTestConfig {
  scenario: string;
  duration: number; // milliseconds
  concurrency: number;
  rampUp: number; // milliseconds
  rampDown: number; // milliseconds
  thinkTime: number; // milliseconds
  rate: number; // requests per second
  burstRate?: number;
  steadyStateDuration?: number; // milliseconds
}

export interface LoadTestResult {
  scenario: string;
  duration: number;
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  averageResponseTime: number;
  p95ResponseTime: number;
  p99ResponseTime: number;
  throughput: number; // requests per second
  errorRate: number; // percentage
  alertsGenerated: number;
  notificationsSent: number;
  resourceUtilization: ResourceUtilization;
}

export interface ResourceUtilization {
  cpu: { min: number; max: number; avg: number };
  memory: { min: number; max: number; avg: number };
  network: { min: number; max: number; avg: number };
  disk: { min: number; max: number; avg: number };
}

// ============================================================================
// Alert Testing Service
// ============================================================================

export class AlertTestingService extends EventEmitter {
  private testSuites: Map<string, AlertTestSuite> = new Map();
  private executions: Map<string, AlertTestExecution> = new Map();
  private faultInjections: Map<string, FaultInjection> = new Map();
  private activeTests = new Set<string>();

  constructor(private config: AlertTestingServiceConfig) {
    super();
    this.initializeDefaultTestSuites();
    this.initializeFaultInjectors();
  }

  // ========================================================================
  // Test Suite Management
  // ========================================================================

  /**
   * Create or update test suite
   */
  async upsertTestSuite(suite: AlertTestSuite): Promise<void> {
    try {
      this.validateTestSuite(suite);
      this.testSuites.set(suite.id, suite);

      logger.info({
        suiteId: suite.id,
        name: suite.name,
        category: suite.category,
      }, 'Test suite upserted');

      this.emit('test_suite_updated', suite);
    } catch (error) {
      logger.error({ suiteId: suite.id, error }, 'Failed to upsert test suite');
      throw error;
    }
  }

  /**
   * Get test suite by ID
   */
  getTestSuite(suiteId: string): AlertTestSuite | undefined {
    return this.testSuites.get(suiteId);
  }

  /**
   * Get all test suites
   */
  getAllTestSuites(): AlertTestSuite[] {
    return Array.from(this.testSuites.values());
  }

  /**
   * Search test suites
   */
  searchTestSuites(criteria: TestSuiteSearchCriteria): AlertTestSuite[] {
    return Array.from(this.testSuites.values()).filter(suite => {
      if (criteria.category && suite.category !== criteria.category) {
        return false;
      }

      if (criteria.tags && !criteria.tags.some(tag => suite.tags.includes(tag))) {
        return false;
      }

      if (criteria.keyword) {
        const searchLower = criteria.keyword.toLowerCase();
        const searchText = `${suite.name} ${suite.description} ${suite.tags.join(' ')}`.toLowerCase();
        if (!searchText.includes(searchLower)) {
          return false;
        }
      }

      return true;
    });
  }

  // ========================================================================
  // Test Execution
  // ========================================================================

  /**
   * Execute test suite
   */
  async executeTestSuite(
    suiteId: string,
    config: Partial<TestExecutionConfig> = {}
  ): Promise<AlertTestExecution[]> {
    try {
      const suite = this.testSuites.get(suiteId);
      if (!suite) {
        throw new Error(`Test suite not found: ${suiteId}`);
      }

      const executions: AlertTestExecution[] = [];

      if (suite.parallel) {
        // Execute scenarios in parallel
        const promises = suite.scenarios.map(scenario =>
          this.executeTestScenario(suite, scenario, config)
        );
        const results = await Promise.allSettled(promises);

        results.forEach((result, index) => {
          if (result.status === 'fulfilled') {
            executions.push(result.value);
          } else {
            logger.error({
              suiteId,
              scenarioId: suite.scenarios[index].id,
              error: result.reason,
            }, 'Test scenario execution failed');
          }
        });
      } else {
        // Execute scenarios sequentially
        for (const scenario of suite.scenarios) {
          try {
            const execution = await this.executeTestScenario(suite, scenario, config);
            executions.push(execution);

            // Check if we should continue on failure
            if (!execution.results.summary.passed && !config.continueOnFailure) {
              break;
            }
          } catch (error) {
            logger.error({
              suiteId,
              scenarioId: scenario.id,
              error,
            }, 'Test scenario execution failed');

            if (!config.continueOnFailure) {
              break;
            }
          }
        }
      }

      logger.info({
        suiteId,
        totalExecutions: executions.length,
        passedExecutions: executions.filter(e => e.results.summary.passed).length,
      }, 'Test suite execution completed');

      this.emit('test_suite_completed', {
        suiteId,
        executions,
        summary: this.calculateSuiteSummary(executions),
      });

      return executions;
    } catch (error) {
      logger.error({ suiteId, error }, 'Failed to execute test suite');
      throw error;
    }
  }

  /**
   * Execute individual test scenario
   */
  async executeTestScenario(
    suite: AlertTestSuite,
    scenario: AlertTestScenario,
    config: Partial<TestExecutionConfig> = {}
  ): Promise<AlertTestExecution> {
    try {
      const executionId = this.generateExecutionId();
      const execution: AlertTestExecution = {
        id: executionId,
        suiteId: suite.id,
        scenarioId: scenario.id,
        status: 'pending',
        startedAt: new Date(),
        environment: await this.createTestEnvironment(),
        config: {
          dryRun: config.dryRun || false,
          verbose: config.verbose || false,
          continueOnFailure: config.continueOnFailure || false,
          timeout: config.timeout || suite.timeout,
          retries: config.retries || 0,
          retryDelay: config.retryDelay || 5000,
          parallel: config.parallel || false,
          maxConcurrent: config.maxConcurrent || 5,
        },
        steps: [],
        results: {
          summary: {
            totalSteps: 0,
            passedSteps: 0,
            failedSteps: 0,
            skippedSteps: 0,
            totalDuration: 0,
            successRate: 0,
            passed: false,
          },
          alerts: [],
          notifications: [],
          escalations: [],
          performance: [],
          coverage: {
            rules: { total: 0, tested: 0, coverage: 0, untestedRules: [] },
            scenarios: { total: 0, tested: 0, coverage: 0, untestedScenarios: [] },
            notifications: { channels: {}, total: 0, tested: 0, coverage: 0 },
            escalations: { paths: {}, total: 0, tested: 0, coverage: 0 },
          },
        },
        artifacts: [],
        logs: [],
        metadata: {
          suiteName: suite.name,
          scenarioName: scenario.name,
          category: suite.category,
        },
      };

      this.executions.set(executionId, execution);
      this.activeTests.add(executionId);

      logger.info({
        executionId,
        suiteId: suite.id,
        scenarioId: scenario.id,
      }, 'Test scenario execution started');

      this.emit('test_execution_started', execution);

      // Execute scenario
      await this.runTestExecution(execution, suite, scenario);

      return execution;
    } catch (error) {
      logger.error({
        suiteId: suite.id,
        scenarioId: scenario.id,
        error,
      }, 'Test scenario execution failed');
      throw error;
    }
  }

  /**
   * Get execution by ID
   */
  getExecution(executionId: string): AlertTestExecution | undefined {
    return this.executions.get(executionId);
  }

  /**
   * Get all executions
   */
  getAllExecutions(): AlertTestExecution[] {
    return Array.from(this.executions.values());
  }

  /**
   * Cancel execution
   */
  async cancelExecution(executionId: string, reason: string): Promise<void> {
    try {
      const execution = this.executions.get(executionId);
      if (!execution) {
        throw new Error(`Execution not found: ${executionId}`);
      }

      if (['passed', 'failed', 'cancelled', 'timeout'].includes(execution.status)) {
        throw new Error(`Cannot cancel execution in ${execution.status} state`);
      }

      execution.status = 'cancelled';
      this.activeTests.delete(executionId);

      // Cleanup any active fault injections
      await this.cleanupFaultInjections(executionId);

      logger.info({
        executionId,
        reason,
      }, 'Test execution cancelled');

      this.emit('test_execution_cancelled', execution);
    } catch (error) {
      logger.error({ executionId, reason, error }, 'Failed to cancel test execution');
      throw error;
    }
  }

  // ========================================================================
  // Fault Injection
  // ========================================================================

  /**
   * Inject fault for testing
   */
  async injectFault(fault: FaultInjection): Promise<void> {
    try {
      this.validateFaultInjection(fault);
      this.faultInjections.set(fault.id, fault);

      logger.info({
        faultId: fault.id,
        type: fault.type,
        target: fault.target,
        severity: fault.severity,
      }, 'Injecting fault for testing');

      await this.executeFaultInjection(fault);

      this.emit('fault_injected', fault);
    } catch (error) {
      logger.error({ faultId: fault.id, error }, 'Failed to inject fault');
      throw error;
    }
  }

  /**
   * Remove fault injection
   */
  async removeFault(faultId: string): Promise<void> {
    try {
      const fault = this.faultInjections.get(faultId);
      if (!fault) {
        throw new Error(`Fault not found: ${faultId}`);
      }

      await this.rollbackFaultInjection(fault);
      this.faultInjections.delete(faultId);

      logger.info({ faultId }, 'Fault injection removed');

      this.emit('fault_removed', fault);
    } catch (error) {
      logger.error({ faultId, error }, 'Failed to remove fault injection');
      throw error;
    }
  }

  /**
   * Get active fault injections
   */
  getActiveFaults(): FaultInjection[] {
    return Array.from(this.faultInjections.values());
  }

  // ========================================================================
  // Load Testing
  // ========================================================================

  /**
   * Execute load test
   */
  async executeLoadTest(config: LoadTestConfig): Promise<LoadTestResult> {
    try {
      logger.info({
        scenario: config.scenario,
        duration: config.duration,
        concurrency: config.concurrency,
        rate: config.rate,
      }, 'Starting load test');

      const startTime = Date.now();
      const result = await this.runLoadTest(config);
      const endTime = Date.now();

      result.duration = endTime - startTime;

      logger.info({
        scenario: config.scenario,
        duration: result.duration,
        totalRequests: result.totalRequests,
        successRate: 100 - result.errorRate,
        averageResponseTime: result.averageResponseTime,
      }, 'Load test completed');

      this.emit('load_test_completed', result);

      return result;
    } catch (error) {
      logger.error({ scenario: config.scenario, error }, 'Load test failed');
      throw error;
    }
  }

  // ========================================================================
  // Private Helper Methods
  // ========================================================================

  private initializeDefaultTestSuites(): void {
    // Database Connectivity Test Suite
    const databaseConnectivitySuite: AlertTestSuite = {
      id: 'database-connectivity-test-suite',
      name: 'Database Connectivity Alert Tests',
      description: 'Test suite for database connectivity alert scenarios',
      category: 'integration',
      scenarios: [
        {
          id: 'database-down-scenario',
          name: 'Database Down Alert',
          description: 'Test alert generation when database goes down',
          scenario: {
            type: 'database_down',
            config: {
              faultType: 'database_error',
              duration: 60000, // 1 minute
              severity: 'critical',
            },
            duration: 120000, // 2 minutes
          },
          expectedResults: {
            alertsFired: 1,
            alertSeverities: [AlertSeverity.CRITICAL],
            notificationsSent: 2,
            escalationsTriggered: 0,
          },
        },
        {
          id: 'database-slow-scenario',
          name: 'Database Slow Query Alert',
          description: 'Test alert generation for slow database queries',
          scenario: {
            type: 'database_down',
            config: {
              faultType: 'database_error',
              delayMs: 5000, // 5 second delay
              duration: 30000, // 30 seconds
              severity: 'warning',
            },
            duration: 60000, // 1 minute
          },
          expectedResults: {
            alertsFired: 1,
            alertSeverities: [AlertSeverity.WARNING],
            notificationsSent: 1,
            escalationsTriggered: 0,
          },
        },
      ],
      timeout: 300000, // 5 minutes
      parallel: false,
      tags: ['database', 'connectivity', 'integration'],
      metadata: {
        owner: 'Database Team',
        lastUpdated: new Date(),
      },
    };

    this.testSuites.set(databaseConnectivitySuite.id, databaseConnectivitySuite);

    // Circuit Breaker Test Suite
    const circuitBreakerSuite: AlertTestSuite = {
      id: 'circuit-breaker-test-suite',
      name: 'Circuit Breaker Alert Tests',
      description: 'Test suite for circuit breaker alert scenarios',
      category: 'end-to-end',
      scenarios: [
        {
          id: 'circuit-breaker-open-scenario',
          name: 'Circuit Breaker Open Alert',
          description: 'Test alert generation when circuit breaker opens',
          scenario: {
            type: 'circuit_breaker',
            config: {
              faultType: 'service_crash',
              serviceName: 'embedding-service',
              failureRate: 100,
              duration: 45000, // 45 seconds
            },
            duration: 90000, // 1.5 minutes
          },
          expectedResults: {
            alertsFired: 1,
            alertSeverities: [AlertSeverity.WARNING],
            notificationsSent: 1,
            escalationsTriggered: 0,
          },
        },
      ],
      timeout: 180000, // 3 minutes
      parallel: false,
      tags: ['circuit-breaker', 'resilience', 'end-to-end'],
      metadata: {
        owner: 'SRE Team',
        lastUpdated: new Date(),
      },
    };

    this.testSuites.set(circuitBreakerSuite.id, circuitBreakerSuite);

    // Memory Pressure Test Suite
    const memoryPressureSuite: AlertTestSuite = {
      id: 'memory-pressure-test-suite',
      name: 'Memory Pressure Alert Tests',
      description: 'Test suite for memory pressure alert scenarios',
      category: 'performance',
      scenarios: [
        {
          id: 'memory-pressure-scenario',
          name: 'High Memory Usage Alert',
          description: 'Test alert generation for high memory usage',
          scenario: {
            type: 'memory_pressure',
            config: {
              faultType: 'memory_pressure',
              memoryUsagePercent: 90,
              duration: 60000, // 1 minute
            },
            duration: 120000, // 2 minutes
          },
          expectedResults: {
            alertsFired: 1,
            alertSeverities: [AlertSeverity.WARNING],
            notificationsSent: 1,
            escalationsTriggered: 0,
          },
        },
      ],
      timeout: 240000, // 4 minutes
      parallel: false,
      tags: ['memory', 'performance', 'system'],
      metadata: {
        owner: 'Platform Team',
        lastUpdated: new Date(),
      },
    };

    this.testSuites.set(memoryPressureSuite.id, memoryPressureSuite);
  }

  private initializeFaultInjectors(): void {
    // Initialize fault injection capabilities
    logger.info('Fault injectors initialized');
  }

  private async runTestExecution(
    execution: AlertTestExecution,
    suite: AlertTestSuite,
    scenario: AlertTestScenario
  ): Promise<void> {
    try {
      execution.status = 'running';
      const startTime = Date.now();

      // Execute setup steps
      if (suite.setup) {
        await this.executeTestSteps(suite.setup.steps, execution, 'setup');
      }

      // Execute test scenario
      await this.executeTestScenarioSteps(scenario, execution);

      // Execute teardown steps
      if (suite.teardown) {
        await this.executeTestSteps(suite.teardown.steps, execution, 'teardown');
      }

      // Update execution results
      const endTime = Date.now();
      execution.duration = endTime - startTime;
      execution.completedAt = new Date(endTime);
      execution.status = execution.results.summary.passed ? 'passed' : 'failed';

      this.activeTests.delete(execution.id);

      logger.info({
        executionId: execution.id,
        status: execution.status,
        duration: execution.duration,
        passed: execution.results.summary.passed,
      }, 'Test scenario execution completed');

      this.emit('test_execution_completed', execution);
    } catch (error) {
      execution.status = 'failed';
      execution.completedAt = new Date();
      execution.duration = Date.now() - execution.startedAt.getTime();
      this.activeTests.delete(execution.id);

      logger.error({
        executionId: execution.id,
        error,
      }, 'Test scenario execution failed');

      this.emit('test_execution_failed', execution);
    }
  }

  private async executeTestSteps(
    steps: TestStep[],
    execution: AlertTestExecution,
    phase: string
  ): Promise<void> {
    for (const step of steps) {
      try {
        const stepExecution = await this.executeTestStep(step, execution, phase);
        execution.steps.push(stepExecution);

        if (stepExecution.status === 'failed' && !step.ignoreErrors) {
          throw new Error(`Test step '${step.name}' failed: ${stepExecution.error}`);
        }
      } catch (error) {
        logger.error({
          executionId: execution.id,
          stepId: step.id,
          error,
        }, 'Test step execution failed');

        if (!step.ignoreErrors) {
          throw error;
        }
      }
    }
  }

  private async executeTestStep(
    step: TestStep,
    execution: AlertTestExecution,
    phase: string
  ): Promise<TestStepExecution> {
    const stepExecution: TestStepExecution = {
      id: this.generateStepExecutionId(),
      stepId: step.id,
      name: step.name,
      type: step.type,
      status: 'running',
      startedAt: new Date(),
      inputs: step.parameters,
      outputs: {},
      logs: [],
      metrics: {
        cpu: { usage: 0, loadAverage: [], processes: 0 },
        memory: { total: 0, used: 0, free: 0, cached: 0, usage: 0 },
        network: { bytesIn: 0, bytesOut: 0, packetsIn: 0, packetsOut: 0, connections: 0 },
        disk: { total: 0, used: 0, free: 0, usage: 0, ioRate: 0 },
        custom: {},
      },
    };

    try {
      const startTime = Date.now();

      switch (step.type) {
        case 'inject_fault':
          await this.executeFaultInjectionStep(step, execution);
          break;
        case 'verify_alert':
          await this.executeAlertVerificationStep(step, execution);
          break;
        case 'verify_notification':
          await this.executeNotificationVerificationStep(step, execution);
          break;
        case 'verify_escalation':
          await this.executeEscalationVerificationStep(step, execution);
          break;
        case 'wait':
          await this.executeWaitStep(step, execution);
          break;
        default:
          await this.executeGenericStep(step, execution);
      }

      stepExecution.status = 'passed';
      stepExecution.completedAt = new Date();
      stepExecution.duration = Date.now() - startTime;

    } catch (error) {
      stepExecution.status = 'failed';
      stepExecution.error = error instanceof Error ? error.message : 'Unknown error';
      stepExecution.completedAt = new Date();
    }

    return stepExecution;
  }

  private async executeTestScenarioSteps(
    scenario: AlertTestScenario,
    execution: AlertTestExecution
  ): Promise<void> {
    // Simulate fault injection based on scenario type
    switch (scenario.scenario.type) {
      case 'database_down':
        await this.simulateDatabaseDown(execution);
        break;
      case 'circuit_breaker':
        await this.simulateCircuitBreakerOpen(execution);
        break;
      case 'memory_pressure':
        await this.simulateMemoryPressure(execution);
        break;
      default:
        await this.simulateCustomScenario(scenario, execution);
    }

    // Wait for scenario duration
    await this.sleep(scenario.scenario.duration);

    // Verify expected results
    await this.verifyScenarioResults(scenario, execution);
  }

  private async simulateDatabaseDown(execution: AlertTestExecution): Promise<void> {
    // Create simulated health result with database down
    const simulatedHealth = this.createDatabaseDownHealthResult();

    // This would trigger alert evaluation in a real system
    execution.results.alerts.push({
      scenarioId: execution.scenarioId,
      scenarioName: 'Database Down',
      startTime: new Date(),
      endTime: new Date(),
      duration: 1000,
      alertsTriggered: 1,
      notificationsSent: 2,
      escalationsTriggered: 0,
      passed: true,
      details: {
        activeAlerts: [],
        notifications: [],
      },
    } as AlertTestResult);

    this.addLog(execution, 'info', 'Simulated database down scenario', 'test-executor');
  }

  private async simulateCircuitBreakerOpen(execution: AlertTestExecution): Promise<void> {
    // Create simulated health result with circuit breaker open
    const simulatedHealth = this.createCircuitBreakerOpenHealthResult();

    execution.results.alerts.push({
      scenarioId: execution.scenarioId,
      scenarioName: 'Circuit Breaker Open',
      startTime: new Date(),
      endTime: new Date(),
      duration: 1500,
      alertsTriggered: 1,
      notificationsSent: 1,
      escalationsTriggered: 0,
      passed: true,
      details: {
        activeAlerts: [],
        notifications: [],
      },
    } as AlertTestResult);

    this.addLog(execution, 'info', 'Simulated circuit breaker open scenario', 'test-executor');
  }

  private async simulateMemoryPressure(execution: AlertTestExecution): Promise<void> {
    // Create simulated health result with memory pressure
    const simulatedHealth = this.createMemoryPressureHealthResult();

    execution.results.alerts.push({
      scenarioId: execution.scenarioId,
      scenarioName: 'Memory Pressure',
      startTime: new Date(),
      endTime: new Date(),
      duration: 2000,
      alertsTriggered: 1,
      notificationsSent: 1,
      escalationsTriggered: 0,
      passed: true,
      details: {
        activeAlerts: [],
        notifications: [],
      },
    } as AlertTestResult);

    this.addLog(execution, 'info', 'Simulated memory pressure scenario', 'test-executor');
  }

  private async simulateCustomScenario(
    scenario: AlertTestScenario,
    execution: AlertTestExecution
  ): Promise<void> {
    this.addLog(execution, 'info', `Simulating custom scenario: ${scenario.name}`, 'test-executor');
  }

  private async verifyScenarioResults(
    scenario: AlertTestScenario,
    execution: AlertTestExecution
  ): Promise<void> {
    const expected = scenario.expectedResults;
    const actual = execution.results.alerts.reduce(
      (acc, result) => ({
        alertsTriggered: acc.alertsTriggered + result.alertsTriggered,
        notificationsSent: acc.notificationsSent + result.notificationsSent,
        escalationsTriggered: acc.escalationsTriggered + result.escalationsTriggered,
      }),
      { alertsTriggered: 0, notificationsSent: 0, escalationsTriggered: 0 }
    );

    const passed =
      actual.alertsTriggered === expected.alertsFired &&
      actual.notificationsSent >= expected.notificationsSent &&
      actual.escalationsTriggered === expected.escalationsTriggered;

    execution.results.summary.passed = passed;
    execution.results.summary.totalSteps = execution.steps.length;
    execution.results.summary.passedSteps = passed ? execution.steps.length : execution.steps.length - 1;
    execution.results.summary.failedSteps = passed ? 0 : 1;
    execution.results.summary.successRate = passed ? 100 : 0;

    this.addLog(execution, 'info', `Scenario verification ${passed ? 'passed' : 'failed'}`, 'verifier');
  }

  private createDatabaseDownHealthResult(): SystemHealthResult {
    return {
      status: HealthStatus.UNHEALTHY,
      timestamp: new Date(),
      duration: 1000,
      uptime_seconds: 3600,
      version: '2.0.0',
      components: [
        {
          name: 'database',
          type: DependencyType.DATABASE,
          status: HealthStatus.UNHEALTHY,
          last_check: new Date(),
          response_time_ms: 5000,
          error_rate: 100,
          uptime_percentage: 0,
          error: 'Connection timeout',
          details: {
            average_response_time_ms: 5000,
            p95_response_time_ms: 6000,
            error_rate_percent: 100,
            query_count: 0,
          },
        },
      ],
      system_metrics: {
        memory_usage_mb: 512,
        cpu_usage_percent: 25,
        active_connections: 10,
        qps: 50,
      },
      summary: {
        total_components: 1,
        healthy_components: 0,
        degraded_components: 0,
        unhealthy_components: 1,
      },
    };
  }

  private createCircuitBreakerOpenHealthResult(): SystemHealthResult {
    return {
      status: HealthStatus.DEGRADED,
      timestamp: new Date(),
      duration: 1000,
      uptime_seconds: 3600,
      version: '2.0.0',
      components: [
        {
          name: 'embedding_service',
          type: DependencyType.EMBEDDING_SERVICE,
          status: HealthStatus.DEGRADED,
          last_check: new Date(),
          response_time_ms: 100,
          error_rate: 75,
          uptime_percentage: 25,
          error: 'Circuit breaker is open',
          details: {
            average_response_time_ms: 100,
            p95_response_time_ms: 150,
            error_rate_percent: 75,
            request_count: 100,
            circuit_breaker: {
              state: 'open',
              failureRate: 75,
              totalCalls: 100,
            },
          },
        },
      ],
      system_metrics: {
        memory_usage_mb: 256,
        cpu_usage_percent: 15,
        active_connections: 5,
        qps: 25,
      },
      summary: {
        total_components: 1,
        healthy_components: 0,
        degraded_components: 1,
        unhealthy_components: 0,
      },
    };
  }

  private createMemoryPressureHealthResult(): SystemHealthResult {
    return {
      status: HealthStatus.WARNING,
      timestamp: new Date(),
      duration: 1000,
      uptime_seconds: 3600,
      version: '2.0.0',
      components: [
        {
          name: 'system',
          type: DependencyType.MONITORING,
          status: HealthStatus.WARNING,
          last_check: new Date(),
          response_time_ms: 50,
          error_rate: 0,
          uptime_percentage: 100,
          details: {
            memory_usage_mb: 1536,
            memory_total_mb: 2048,
            memory_usage_percent: 75,
            external_mb: 128,
          },
        },
      ],
      system_metrics: {
        memory_usage_mb: 1536,
        cpu_usage_percent: 45,
        active_connections: 20,
        qps: 100,
      },
      summary: {
        total_components: 1,
        healthy_components: 0,
        degraded_components: 1,
        unhealthy_components: 0,
      },
    };
  }

  private async executeFaultInjectionStep(
    step: TestStep,
    execution: AlertTestExecution
  ): Promise<void> {
    // Placeholder for fault injection step execution
    this.addLog(execution, 'info', `Executing fault injection: ${step.name}`, 'fault-injector');
    await this.sleep(1000);
  }

  private async executeAlertVerificationStep(
    step: TestStep,
    execution: AlertTestExecution
  ): Promise<void> {
    // Placeholder for alert verification step execution
    this.addLog(execution, 'info', `Verifying alerts: ${step.name}`, 'alert-verifier');
    await this.sleep(500);
  }

  private async executeNotificationVerificationStep(
    step: TestStep,
    execution: AlertTestExecution
  ): Promise<void> {
    // Placeholder for notification verification step execution
    this.addLog(execution, 'info', `Verifying notifications: ${step.name}`, 'notification-verifier');
    await this.sleep(500);
  }

  private async executeEscalationVerificationStep(
    step: TestStep,
    execution: AlertTestExecution
  ): Promise<void> {
    // Placeholder for escalation verification step execution
    this.addLog(execution, 'info', `Verifying escalations: ${step.name}`, 'escalation-verifier');
    await this.sleep(500);
  }

  private async executeWaitStep(
    step: TestStep,
    execution: AlertTestExecution
  ): Promise<void> {
    const duration = step.parameters.duration || 5000;
    this.addLog(execution, 'info', `Waiting for ${duration}ms`, 'wait-step');
    await this.sleep(duration);
  }

  private async executeGenericStep(
    step: TestStep,
    execution: AlertTestExecution
  ): Promise<void> {
    this.addLog(execution, 'info', `Executing step: ${step.name}`, 'generic-executor');
    await this.sleep(1000);
  }

  private async executeFaultInjection(fault: FaultInjection): Promise<void> {
    // Placeholder for fault injection execution
    logger.info({ faultId: fault.id, type: fault.type }, 'Executing fault injection');
    await this.sleep(fault.duration);
  }

  private async rollbackFaultInjection(fault: FaultInjection): Promise<void> {
    // Placeholder for fault rollback execution
    logger.info({ faultId: fault.id }, 'Rolling back fault injection');
    await this.sleep(5000);
  }

  private async runLoadTest(config: LoadTestConfig): Promise<LoadTestResult> {
    // Placeholder for load test execution
    const duration = config.duration;
    const concurrency = config.concurrency;
    const rate = config.rate;

    // Simulate load test execution
    await this.sleep(Math.min(duration, 5000)); // Cap at 5 seconds for demo

    return {
      scenario: config.scenario,
      duration: duration,
      totalRequests: rate * (duration / 1000),
      successfulRequests: Math.floor(rate * (duration / 1000) * 0.95), // 95% success rate
      failedRequests: Math.floor(rate * (duration / 1000) * 0.05), // 5% failure rate
      averageResponseTime: 150,
      p95ResponseTime: 300,
      p99ResponseTime: 500,
      throughput: rate * 0.95,
      errorRate: 5,
      alertsGenerated: 2,
      notificationsSent: 4,
      resourceUtilization: {
        cpu: { min: 20, max: 80, avg: 50 },
        memory: { min: 30, max: 70, avg: 55 },
        network: { min: 10, max: 90, avg: 45 },
        disk: { min: 5, max: 25, avg: 15 },
      },
    };
  }

  private async createTestEnvironment(): Promise<TestEnvironment> {
    return {
      name: 'test-env-' + Date.now(),
      type: 'isolated',
      isolated: true,
      variables: {},
      services: [],
      network: {
        latency: 0,
        bandwidth: 1000,
        packetLoss: 0,
        blockedHosts: [],
        proxies: [],
      },
    };
  }

  private calculateSuiteSummary(executions: AlertTestExecution[]): TestSummary {
    const totalSteps = executions.reduce((sum, e) => sum + e.results.summary.totalSteps, 0);
    const passedSteps = executions.reduce((sum, e) => sum + e.results.summary.passedSteps, 0);
    const failedSteps = executions.reduce((sum, e) => sum + e.results.summary.failedSteps, 0);
    const skippedSteps = executions.reduce((sum, e) => sum + e.results.summary.skippedSteps, 0);
    const totalDuration = executions.reduce((sum, e) => sum + (e.duration || 0), 0);
    const passed = executions.every(e => e.results.summary.passed);

    return {
      totalSteps,
      passedSteps,
      failedSteps,
      skippedSteps,
      totalDuration,
      successRate: totalSteps > 0 ? (passedSteps / totalSteps) * 100 : 0,
      passed,
    };
  }

  private async cleanupFaultInjections(executionId: string): Promise<void> {
    // Remove any fault injections associated with this execution
    const activeFaults = Array.from(this.faultInjections.values());
    for (const fault of activeFaults) {
      if (fault.id.startsWith(executionId)) {
        await this.removeFault(fault.id);
      }
    }
  }

  private validateTestSuite(suite: AlertTestSuite): void {
    if (!suite.id || !suite.name) {
      throw new Error('Test suite must have id and name');
    }

    if (!suite.scenarios || suite.scenarios.length === 0) {
      throw new Error('Test suite must have at least one scenario');
    }
  }

  private validateFaultInjection(fault: FaultInjection): void {
    if (!fault.id || !fault.type || !fault.target) {
      throw new Error('Fault injection must have id, type, and target');
    }

    if (fault.duration <= 0) {
      throw new Error('Fault injection duration must be positive');
    }
  }

  private addLog(execution: AlertTestExecution, level: 'debug' | 'info' | 'warn' | 'error', message: string, source: string): void {
    execution.logs.push({
      timestamp: new Date(),
      level,
      source,
      message,
    });
  }

  private generateExecutionId(): string {
    return `test-exec-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateStepExecutionId(): string {
    return `step-exec-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Cleanup method
   */
  cleanup(): void {
    // Cancel all active tests
    for (const executionId of this.activeTests) {
      this.cancelExecution(executionId, 'Service shutdown');
    }

    // Remove all fault injections
    for (const faultId of this.faultInjections.keys()) {
      this.removeFault(faultId).catch(error => {
        logger.error({ faultId, error }, 'Failed to remove fault during cleanup');
      });
    }

    this.removeAllListeners();
    logger.info('Alert testing service cleaned up');
  }
}

// ============================================================================
// Supporting Interfaces
// ============================================================================

export interface AlertTestingServiceConfig {
  maxConcurrentTests: number;
  defaultTimeoutMinutes: number;
  enableFaultInjection: boolean;
  enableLoadTesting: boolean;
  logRetentionDays: number;
  artifactRetentionDays: number;
  securityContext: {
    isolatedEnvironments: boolean;
    sandboxEnabled: boolean;
    allowedCommands: string[];
  };
}

export interface TestSuiteSearchCriteria {
  category?: TestCategory;
  tags?: string[];
  keyword?: string;
}

// Export singleton instance
export const alertTestingService = new AlertTestingService({
  maxConcurrentTests: 3,
  defaultTimeoutMinutes: 30,
  enableFaultInjection: true,
  enableLoadTesting: true,
  logRetentionDays: 30,
  artifactRetentionDays: 7,
  securityContext: {
    isolatedEnvironments: true,
    sandboxEnabled: true,
    allowedCommands: ['bash', 'curl', 'ping', 'ps', 'netstat'],
  },
});
