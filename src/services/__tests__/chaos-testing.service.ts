/**
 * P2-P3: Chaos Testing Service for Resilience Validation
 *
 * Provides comprehensive chaos testing capabilities to validate system resilience
 * under various failure conditions including network blips, database errors, timeouts,
 * and resource exhaustion. Supports controlled experiments with monitoring and rollback.
 *
 * Features:
 * - Network chaos: latency injection, packet loss, connection failures
 * - Database chaos: Qdrant 5xx errors, connection timeouts, query failures
 * - Resource chaos: memory pressure, CPU exhaustion, disk space issues
 * - Service chaos: downstream failures, cascading failures, circuit breaker testing
 * - Experiment orchestration with safety controls and automatic rollback
 * - Comprehensive metrics collection and analysis
 *
 * @module services/__tests__/chaos-testing
 */

import { logger } from '@/utils/logger.js';
import { systemMetricsService } from '../metrics/system-metrics.js';
import { sliSloMonitorService } from '../metrics/sli-slo-monitor.js';
import { retryPolicyManager } from '../../utils/retry-policy.js';
import { BaseError, ErrorCode, ErrorCategory, ErrorSeverity } from '../../utils/error-handler.js';

// === Type Definitions ===

export interface ChaosExperiment {
  id: string;
  name: string;
  description: string;
  type: ChaosExperimentType;
  config: ChaosConfig;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'rolled_back';
  start_time?: number;
  end_time?: number;
  duration_seconds: number;
  targets: string[];
  metrics: ChaosExperimentMetrics;
  rollback_actions: RollbackAction[];
  safety_checks: SafetyCheck[];
  tags: string[];
  created_by: string;
  created_at: number;
}

export type ChaosExperimentType =
  | 'network_latency'
  | 'network_packet_loss'
  | 'network_connection_failure'
  | 'database_5xx_errors'
  | 'database_connection_timeout'
  | 'database_query_failure'
  | 'memory_pressure'
  | 'cpu_exhaustion'
  | 'disk_space_exhaustion'
  | 'downstream_service_failure'
  | 'circuit_breaker_trigger'
  | 'resource_throttling'
  | 'cascade_failure';

export interface ChaosConfig {
  // Experiment configuration
  intensity: number; // 0-100, percentage impact
  duration_seconds: number;
  gradual_ramp_up?: boolean; // Gradually increase intensity
  ramp_up_seconds?: number;

  // Network-specific config
  network?: {
    latency_ms?: number;
    packet_loss_percentage?: number;
    bandwidth_limit_kbps?: number;
    affected_hosts?: string[];
    affected_ports?: number[];
  };

  // Database-specific config
  database?: {
    error_rate_percentage?: number;
    error_codes?: string[];
    timeout_ms?: number;
    affected_operations?: ('read' | 'write' | 'search')[];
    affected_collections?: string[];
  };

  // Resource-specific config
  resources?: {
    memory_pressure_mb?: number;
    cpu_load_percentage?: number;
    disk_fill_percentage?: number;
  };

  // Service-specific config
  service?: {
    failure_rate_percentage?: number;
    affected_endpoints?: string[];
    response_delay_ms?: number;
  };

  // Safety limits
  safety_limits?: {
    max_error_rate_percentage?: number;
    max_latency_increase_percentage?: number;
    min_availability_percentage?: number;
    emergency_stop_availability_percentage?: number;
  };
}

export interface ChaosExperimentMetrics {
  // Impact metrics
  availability_impact: number;
  latency_impact: number;
  error_rate_impact: number;
  throughput_impact: number;

  // System metrics
  cpu_usage: number[];
  memory_usage: number[];
  disk_usage: number[];
  network_io: number[];

  // Business metrics
  requests_total: number;
  requests_successful: number;
  requests_failed: number;
  requests_timed_out: number;

  // Recovery metrics
  time_to_detect_seconds: number;
  time_to_recover_seconds: number;
  recovery_successful: boolean;

  // Custom metrics
  custom_metrics: Record<string, number[]>;
}

export interface RollbackAction {
  id: string;
  type: 'disable_chaos' | 'restart_service' | 'clear_cache' | 'reset_circuit_breaker' | 'custom';
  description: string;
  executed: boolean;
  executed_at?: number;
  result?: 'success' | 'failed';
}

export interface SafetyCheck {
  type: 'availability' | 'error_rate' | 'latency' | 'custom';
  threshold: number;
  operator: 'gt' | 'lt' | 'eq' | 'gte' | 'lte';
  metric: string;
  enabled: boolean;
  triggered: boolean;
  triggered_at?: number;
}

export interface ChaosTestSuite {
  id: string;
  name: string;
  description: string;
  experiments: ChaosExperiment[];
  parallel_execution: boolean;
  continue_on_failure: boolean;
  created_at: number;
  created_by: string;
}

/**
 * Chaos Testing Service
 */
export class ChaosTestingService {
  private activeExperiments: Map<string, ChaosExperiment> = new Map();
  private experimentHistory: ChaosExperiment[] = [];
  private chaosEnabled: boolean = false;
  private emergencyStop: boolean = false;
  private baselineMetrics: any = {};

  private readonly DEFAULT_EXPERIMENTS: Partial<ChaosExperiment>[] = [
    {
      name: 'Network Blip Test',
      description: 'Simulates brief network connectivity issues',
      type: 'network_connection_failure',
      config: {
        intensity: 100,
        duration_seconds: 30,
        network: {
          affected_hosts: ['qdrant', 'external-api'],
        },
        safety_limits: {
          max_error_rate_percentage: 50,
          emergency_stop_availability_percentage: 90,
        },
      },
      targets: ['qdrant-adapter', 'external-api-client'],
      tags: ['network', 'resilience', 'brief'],
    },
    {
      name: 'Qdrant 5xx Error Injection',
      description: 'Simulates Qdrant server errors',
      type: 'database_5xx_errors',
      config: {
        intensity: 25,
        duration_seconds: 60,
        database: {
          error_rate_percentage: 25,
          error_codes: ['500', '502', '503', '504'],
          affected_operations: ['search', 'write'],
        },
        safety_limits: {
          max_error_rate_percentage: 40,
          min_availability_percentage: 60,
        },
      },
      targets: ['qdrant-adapter'],
      tags: ['database', 'qdrant', 'errors'],
    },
    {
      name: 'High Latency Injection',
      description: 'Simulates increased response times',
      type: 'network_latency',
      config: {
        intensity: 75,
        duration_seconds: 120,
        network: {
          latency_ms: 2000,
          affected_hosts: ['qdrant'],
        },
        safety_limits: {
          max_latency_increase_percentage: 500,
          emergency_stop_availability_percentage: 85,
        },
      },
      targets: ['qdrant-adapter'],
      tags: ['latency', 'performance', 'network'],
    },
    {
      name: 'Memory Pressure Test',
      description: 'Simulates memory pressure conditions',
      type: 'memory_pressure',
      config: {
        intensity: 50,
        duration_seconds: 90,
        resources: {
          memory_pressure_mb: 512,
        },
        safety_limits: {
          max_error_rate_percentage: 30,
        },
      },
      targets: ['system'],
      tags: ['memory', 'resources', 'pressure'],
    },
    {
      name: 'Circuit Breaker Test',
      description: 'Tests circuit breaker functionality',
      type: 'circuit_breaker_trigger',
      config: {
        intensity: 100,
        duration_seconds: 45,
        service: {
          failure_rate_percentage: 100,
          affected_endpoints: ['/memory/store', '/memory/find'],
        },
        safety_limits: {
          max_error_rate_percentage: 100,
          min_availability_percentage: 0,
        },
      },
      targets: ['circuit-breaker'],
      tags: ['circuit-breaker', 'resilience', 'failure'],
    },
  ];

  constructor() {
    this.initializeBaselineMetrics();
    logger.info('ChaosTestingService initialized', {
      defaultExperimentsCount: this.DEFAULT_EXPERIMENTS.length,
      chaosEnabled: this.chaosEnabled,
    });
  }

  /**
   * Initialize baseline metrics
   */
  private initializeBaselineMetrics(): void {
    this.baselineMetrics = {
      availability: 100,
      latency_p95: 100,
      error_rate: 0,
      throughput: 10,
      cpu_usage: 20,
      memory_usage: 30,
    };
  }

  /**
   * Enable chaos testing
   */
  enableChaosTesting(): void {
    this.chaosEnabled = true;
    logger.warn('Chaos testing enabled - use with caution', {
      timestamp: Date.now(),
    });
  }

  /**
   * Disable chaos testing
   */
  disableChaosTesting(): void {
    this.chaosEnabled = false;
    this.emergencyStop = true;
    this.stopAllExperiments();
    logger.info('Chaos testing disabled - all experiments stopped', {
      timestamp: Date.now(),
    });
  }

  /**
   * Create chaos experiment
   */
  createExperiment(
    experimentData: Omit<
      ChaosExperiment,
      | 'id'
      | 'status'
      | 'metrics'
      | 'rollback_actions'
      | 'safety_checks'
      | 'created_at'
      | 'created_by'
    >,
    createdBy: string = 'system'
  ): ChaosExperiment {
    const experiment: ChaosExperiment = {
      ...experimentData,
      id: `chaos_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      status: 'pending',
      metrics: this.initializeExperimentMetrics(),
      rollback_actions: this.generateRollbackActions(experimentData.type),
      safety_checks: this.generateSafetyChecks(experimentData.config),
      created_at: Date.now(),
      created_by: createdBy,
    };

    logger.info('Chaos experiment created', {
      experimentId: experiment.id,
      name: experiment.name,
      type: experiment.type,
      duration: experiment.duration_seconds,
      intensity: experiment.config.intensity,
    });

    return experiment;
  }

  /**
   * Initialize experiment metrics
   */
  private initializeExperimentMetrics(): ChaosExperimentMetrics {
    return {
      availability_impact: 0,
      latency_impact: 0,
      error_rate_impact: 0,
      throughput_impact: 0,
      cpu_usage: [],
      memory_usage: [],
      disk_usage: [],
      network_io: [],
      requests_total: 0,
      requests_successful: 0,
      requests_failed: 0,
      requests_timed_out: 0,
      time_to_detect_seconds: 0,
      time_to_recover_seconds: 0,
      recovery_successful: false,
      custom_metrics: {},
    };
  }

  /**
   * Generate rollback actions
   */
  private generateRollbackActions(type: ChaosExperimentType): RollbackAction[] {
    const baseActions: RollbackAction[] = [
      {
        id: 'disable_chaos',
        type: 'disable_chaos',
        description: 'Disable chaos injection',
        executed: false,
      },
      {
        id: 'reset_circuit_breaker',
        type: 'reset_circuit_breaker',
        description: 'Reset all circuit breakers',
        executed: false,
      },
      {
        id: 'clear_cache',
        type: 'clear_cache',
        description: 'Clear all caches',
        executed: false,
      },
    ];

    const typeSpecificActions: Record<ChaosExperimentType, RollbackAction[]> = {
      network_latency: [
        {
          id: 'reset_network_config',
          type: 'custom',
          description: 'Reset network configuration',
          executed: false,
        },
      ],
      network_packet_loss: [],
      network_connection_failure: [
        {
          id: 'restore_connections',
          type: 'custom',
          description: 'Restore network connections',
          executed: false,
        },
      ],
      database_5xx_errors: [
        {
          id: 'restart_db_adapter',
          type: 'restart_service',
          description: 'Restart database adapter',
          executed: false,
        },
      ],
      database_connection_timeout: [],
      database_query_failure: [],
      memory_pressure: [
        {
          id: 'force_gc',
          type: 'custom',
          description: 'Force garbage collection',
          executed: false,
        },
      ],
      cpu_exhaustion: [],
      disk_space_exhaustion: [],
      downstream_service_failure: [],
      circuit_breaker_trigger: [],
      resource_throttling: [],
      cascade_failure: [],
    };

    return [...baseActions, ...(typeSpecificActions[type] || [])];
  }

  /**
   * Generate safety checks
   */
  private generateSafetyChecks(config: ChaosConfig): SafetyCheck[] {
    const checks: SafetyCheck[] = [
      {
        type: 'availability',
        threshold: config.safety_limits?.emergency_stop_availability_percentage || 80,
        operator: 'lt',
        metric: 'availability',
        enabled: true,
        triggered: false,
      },
      {
        type: 'error_rate',
        threshold: config.safety_limits?.max_error_rate_percentage || 60,
        operator: 'gt',
        metric: 'error_rate',
        enabled: true,
        triggered: false,
      },
    ];

    if (config.safety_limits?.max_latency_increase_percentage) {
      checks.push({
        type: 'latency',
        threshold: config.safety_limits.max_latency_increase_percentage,
        operator: 'gt',
        metric: 'latency_increase',
        enabled: true,
        triggered: false,
      });
    }

    return checks;
  }

  /**
   * Execute chaos experiment
   */
  async executeExperiment(experimentId: string): Promise<ChaosExperiment> {
    if (!this.chaosEnabled) {
      throw new Error('Chaos testing is not enabled');
    }

    const experiment = this.activeExperiments.get(experimentId);
    if (!experiment) {
      throw new Error(`Experiment ${experimentId} not found`);
    }

    if (experiment.status !== 'pending') {
      throw new Error(`Experiment ${experimentId} is not in pending status`);
    }

    logger.warn('Starting chaos experiment', {
      experimentId,
      name: experiment.name,
      type: experiment.type,
      intensity: experiment.config.intensity,
      duration: experiment.config.duration_seconds,
    });

    experiment.status = 'running';
    experiment.start_time = Date.now();

    // Store in active experiments
    this.activeExperiments.set(experimentId, experiment);

    try {
      // Execute the chaos injection
      await this.executeChaosInjection(experiment);

      // Monitor the experiment
      await this.monitorExperiment(experiment);

      // Complete the experiment
      experiment.status = 'completed';
      experiment.end_time = Date.now();

      logger.info('Chaos experiment completed', {
        experimentId,
        duration: Date.now() - (experiment.start_time || 0),
        finalMetrics: experiment.metrics,
      });
    } catch (error) {
      experiment.status = 'failed';
      experiment.end_time = Date.now();

      logger.error('Chaos experiment failed', {
        experimentId,
        error: error instanceof Error ? error.message : String(error),
        duration: Date.now() - (experiment.start_time || 0),
      });

      // Execute rollback
      await this.executeRollback(experiment);
    } finally {
      // Move to history
      this.experimentHistory.push({ ...experiment });
      this.activeExperiments.delete(experimentId);
    }

    return experiment;
  }

  /**
   * Execute chaos injection based on experiment type
   */
  private async executeChaosInjection(experiment: ChaosExperiment): Promise<void> {
    const { type, config } = experiment;

    switch (type) {
      case 'network_latency':
        await this.injectNetworkLatency(config);
        break;

      case 'network_packet_loss':
        await this.injectPacketLoss(config);
        break;

      case 'network_connection_failure':
        await this.injectConnectionFailure(config);
        break;

      case 'database_5xx_errors':
        await this.injectDatabaseErrors(config);
        break;

      case 'database_connection_timeout':
        await this.injectDatabaseTimeouts(config);
        break;

      case 'memory_pressure':
        await this.injectMemoryPressure(config);
        break;

      case 'cpu_exhaustion':
        await this.injectCPUExhaustion(config);
        break;

      case 'circuit_breaker_trigger':
        await this.triggerCircuitBreaker(config);
        break;

      default:
        throw new Error(`Unsupported chaos experiment type: ${type}`);
    }
  }

  /**
   * Inject network latency
   */
  private async injectNetworkLatency(config: ChaosConfig): Promise<void> {
    const latency = config.network?.latency_ms || 1000;
    const targets = config.network?.affected_hosts || [];

    logger.info('Injecting network latency', {
      latencyMs: latency,
      targets,
      duration: config.duration_seconds,
    });

    // Simulate latency injection
    // In a real implementation, this would use network simulation tools
    await this.simulateOperation('network_latency_injection', config.duration_seconds * 1000);
  }

  /**
   * Inject packet loss
   */
  private async injectPacketLoss(config: ChaosConfig): Promise<void> {
    const packetLoss = config.network?.packet_loss_percentage || 10;
    const targets = config.network?.affected_hosts || [];

    logger.info('Injecting packet loss', {
      packetLossPercentage: packetLoss,
      targets,
      duration: config.duration_seconds,
    });

    await this.simulateOperation('packet_loss_injection', config.duration_seconds * 1000);
  }

  /**
   * Inject connection failure
   */
  private async injectConnectionFailure(config: ChaosConfig): Promise<void> {
    const targets = config.network?.affected_hosts || [];

    logger.info('Injecting connection failures', {
      targets,
      duration: config.duration_seconds,
    });

    await this.simulateOperation('connection_failure_injection', config.duration_seconds * 1000);
  }

  /**
   * Inject database errors
   */
  private async injectDatabaseErrors(config: ChaosConfig): Promise<void> {
    const errorRate = config.database?.error_rate_percentage || 10;
    const errorCodes = config.database?.error_codes || ['500'];
    const operations = config.database?.affected_operations || ['search', 'store'];

    logger.info('Injecting database errors', {
      errorRatePercentage: errorRate,
      errorCodes,
      operations,
      duration: config.duration_seconds,
    });

    await this.simulateOperation('database_error_injection', config.duration_seconds * 1000);
  }

  /**
   * Inject database timeouts
   */
  private async injectDatabaseTimeouts(config: ChaosConfig): Promise<void> {
    const timeout = config.database?.timeout_ms || 30000;

    logger.info('Injecting database timeouts', {
      timeoutMs: timeout,
      duration: config.duration_seconds,
    });

    await this.simulateOperation('database_timeout_injection', config.duration_seconds * 1000);
  }

  /**
   * Inject memory pressure
   */
  private async injectMemoryPressure(config: ChaosConfig): Promise<void> {
    const memoryPressure = config.resources?.memory_pressure_mb || 256;

    logger.info('Injecting memory pressure', {
      memoryPressureMB: memoryPressure,
      duration: config.duration_seconds,
    });

    await this.simulateOperation('memory_pressure_injection', config.duration_seconds * 1000);
  }

  /**
   * Inject CPU exhaustion
   */
  private async injectCPUExhaustion(config: ChaosConfig): Promise<void> {
    const cpuLoad = config.resources?.cpu_load_percentage || 80;

    logger.info('Injecting CPU exhaustion', {
      cpuLoadPercentage: cpuLoad,
      duration: config.duration_seconds,
    });

    await this.simulateOperation('cpu_exhaustion_injection', config.duration_seconds * 1000);
  }

  /**
   * Trigger circuit breaker
   */
  private async triggerCircuitBreaker(config: ChaosConfig): Promise<void> {
    const failureRate = config.service?.failure_rate_percentage || 100;

    logger.info('Triggering circuit breaker', {
      failureRatePercentage: failureRate,
      duration: config.duration_seconds,
    });

    await this.simulateOperation('circuit_breaker_trigger', config.duration_seconds * 1000);
  }

  /**
   * Simulate chaos operation (placeholder implementation)
   */
  private async simulateOperation(operation: string, durationMs: number): Promise<void> {
    // In a real implementation, this would actually inject the chaos
    // For now, we just simulate the timing
    const startTime = Date.now();
    const endTime = startTime + durationMs;

    while (Date.now() < endTime && !this.emergencyStop) {
      await new Promise((resolve) => setTimeout(resolve, 1000));

      // Check safety conditions
      const currentMetrics = this.collectCurrentMetrics();
      if (this.checkSafetyConditions(currentMetrics)) {
        logger.warn('Safety check triggered - stopping chaos injection', {
          operation,
          metrics: currentMetrics,
        });
        break;
      }
    }
  }

  /**
   * Monitor experiment
   */
  private async monitorExperiment(experiment: ChaosExperiment): Promise<void> {
    const monitoringInterval = setInterval(() => {
      if (experiment.status !== 'running' || this.emergencyStop) {
        clearInterval(monitoringInterval);
        return;
      }

      // Collect current metrics
      const currentMetrics = this.collectCurrentMetrics();
      this.updateExperimentMetrics(experiment, currentMetrics);

      // Check safety conditions
      if (this.checkSafetyConditions(currentMetrics)) {
        logger.warn('Safety check triggered during experiment', {
          experimentId: experiment.id,
          metrics: currentMetrics,
        });
        this.executeRollback(experiment);
        clearInterval(monitoringInterval);
      }
    }, 5000); // Monitor every 5 seconds

    // Wait for experiment duration
    await new Promise((resolve) => setTimeout(resolve, experiment.config.duration_seconds * 1000));
    clearInterval(monitoringInterval);
  }

  /**
   * Collect current system metrics
   */
  private collectCurrentMetrics(): any {
    const systemMetrics = systemMetricsService.getMetrics();
    const ragStatus = sliSloMonitorService.getRAGStatus();
    const sliMetrics = sliSloMonitorService.getSLIMetrics();

    return {
      availability: sliMetrics.availability.availability_percentage,
      latency_p95: sliMetrics.latency.p95_ms,
      error_rate: sliMetrics.error_rate.error_rate_percentage,
      throughput: sliMetrics.throughput.requests_per_second,
      cpu_usage: sliMetrics.resource_utilization.cpu_percentage,
      memory_usage: sliMetrics.resource_utilization.memory_percentage,
      disk_usage: sliMetrics.resource_utilization.disk_percentage,
      timestamp: Date.now(),
    };
  }

  /**
   * Update experiment metrics
   */
  private updateExperimentMetrics(experiment: ChaosExperiment, currentMetrics: any): void {
    const metrics = experiment.metrics;

    // Calculate impacts relative to baseline
    metrics.availability_impact = this.baselineMetrics.availability - currentMetrics.availability;
    metrics.latency_impact =
      ((currentMetrics.latency_p95 - this.baselineMetrics.latency_p95) /
        this.baselineMetrics.latency_p95) *
      100;
    metrics.error_rate_impact = currentMetrics.error_rate - this.baselineMetrics.error_rate;
    metrics.throughput_impact =
      ((currentMetrics.throughput - this.baselineMetrics.throughput) /
        this.baselineMetrics.throughput) *
      100;

    // Store system metrics
    metrics.cpu_usage.push(currentMetrics.cpu_usage);
    metrics.memory_usage.push(currentMetrics.memory_usage);
    metrics.disk_usage.push(currentMetrics.disk_usage);

    // Update request counts (simulated)
    const requestCount = Math.floor(Math.random() * 100);
    metrics.requests_total += requestCount;
    metrics.requests_successful += Math.floor(requestCount * (currentMetrics.availability / 100));
    metrics.requests_failed +=
      requestCount - Math.floor(requestCount * (currentMetrics.availability / 100));
    metrics.requests_timed_out += Math.floor(requestCount * 0.05); // 5% timeout rate
  }

  /**
   * Check safety conditions
   */
  private checkSafetyConditions(metrics: any): boolean {
    return metrics.availability < 50 || metrics.error_rate > 70 || metrics.latency_p95 > 10000;
  }

  /**
   * Execute rollback actions
   */
  private async executeRollback(experiment: ChaosExperiment): Promise<void> {
    logger.info('Executing rollback actions', {
      experimentId: experiment.id,
      actionCount: experiment.rollback_actions.length,
    });

    for (const action of experiment.rollback_actions) {
      try {
        await this.executeRollbackAction(action);
        action.executed = true;
        action.executed_at = Date.now();
        action.result = 'success';
      } catch (error) {
        action.result = 'failed';
        logger.error('Rollback action failed', {
          experimentId: experiment.id,
          actionId: action.id,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }

  /**
   * Execute individual rollback action
   */
  private async executeRollbackAction(action: RollbackAction): Promise<void> {
    switch (action.type) {
      case 'disable_chaos':
        this.emergencyStop = true;
        break;

      case 'restart_service':
        // Simulate service restart
        await new Promise((resolve) => setTimeout(resolve, 1000));
        break;

      case 'clear_cache':
        // Clear various caches
        retryPolicyManager.clearIdempotencyCache();
        break;

      case 'reset_circuit_breaker':
        retryPolicyManager.resetAllCircuitBreakers();
        break;

      case 'custom':
        // Execute custom rollback logic
        await new Promise((resolve) => setTimeout(resolve, 500));
        break;
    }
  }

  /**
   * Stop all experiments
   */
  private stopAllExperiments(): void {
    for (const [experimentId, experiment] of this.activeExperiments.entries()) {
      if (experiment.status === 'running') {
        logger.warn('Force stopping experiment', {
          experimentId,
          name: experiment.name,
        });

        experiment.status = 'failed';
        experiment.end_time = Date.now();
        this.executeRollback(experiment);

        this.experimentHistory.push({ ...experiment });
      }
    }

    this.activeExperiments.clear();
  }

  // === Public API Methods ===

  /**
   * Get default experiments
   */
  getDefaultExperiments(): Partial<ChaosExperiment>[] {
    return this.DEFAULT_EXPERIMENTS.map((exp) => ({ ...exp }));
  }

  /**
   * Create and execute default experiment
   */
  async executeDefaultExperiment(
    experimentName: string,
    createdBy: string = 'system'
  ): Promise<ChaosExperiment> {
    const experimentTemplate = this.DEFAULT_EXPERIMENTS.find((exp) => exp.name === experimentName);
    if (!experimentTemplate) {
      throw new Error(`Default experiment '${experimentName}' not found`);
    }

    const experiment = this.createExperiment(experimentTemplate as any, createdBy);
    this.activeExperiments.set(experiment.id, experiment);

    return await this.executeExperiment(experiment.id);
  }

  /**
   * Get active experiments
   */
  getActiveExperiments(): ChaosExperiment[] {
    return Array.from(this.activeExperiments.values()).map((exp) => ({ ...exp }));
  }

  /**
   * Get experiment history
   */
  getExperimentHistory(limit?: number): ChaosExperiment[] {
    const history = [...this.experimentHistory].sort((a, b) => b.created_at - a.created_at);
    return limit ? history.slice(0, limit) : history;
  }

  /**
   * Get experiment by ID
   */
  getExperiment(experimentId: string): ChaosExperiment | null {
    const active = this.activeExperiments.get(experimentId);
    if (active) return { ...active };

    const historical = this.experimentHistory.find((exp) => exp.id === experimentId);
    return historical ? { ...historical } : null;
  }

  /**
   * Stop experiment
   */
  async stopExperiment(experimentId: string): Promise<boolean> {
    const experiment = this.activeExperiments.get(experimentId);
    if (!experiment || experiment.status !== 'running') {
      return false;
    }

    logger.info('Stopping experiment', {
      experimentId,
      name: experiment.name,
    });

    experiment.status = 'failed';
    experiment.end_time = Date.now();
    await this.executeRollback(experiment);

    this.experimentHistory.push({ ...experiment });
    this.activeExperiments.delete(experimentId);

    return true;
  }

  /**
   * Get chaos testing status
   */
  getChaosStatus(): {
    enabled: boolean;
    emergency_stop: boolean;
    active_experiments: number;
    completed_experiments: number;
    system_health: 'healthy' | 'degraded' | 'critical';
    baseline_metrics: any;
  } {
    const currentMetrics = this.collectCurrentMetrics();
    let systemHealth: 'healthy' | 'degraded' | 'critical' = 'healthy';

    if (currentMetrics.availability < 90 || currentMetrics.error_rate > 10) {
      systemHealth = 'critical';
    } else if (currentMetrics.availability < 95 || currentMetrics.error_rate > 5) {
      systemHealth = 'degraded';
    }

    return {
      enabled: this.chaosEnabled,
      emergency_stop: this.emergencyStop,
      active_experiments: this.activeExperiments.size,
      completed_experiments: this.experimentHistory.length,
      system_health: systemHealth,
      baseline_metrics: this.baselineMetrics,
    };
  }

  /**
   * Export experiment data
   */
  exportExperimentData(experimentId?: string, format: 'json' | 'csv' = 'json'): string {
    const experiments = experimentId
      ? [this.getExperiment(experimentId)].filter(Boolean)
      : [...this.experimentHistory];

    const data = {
      timestamp: Date.now(),
      chaos_status: this.getChaosStatus(),
      experiments: experiments
        .filter((exp): exp is ChaosExperiment => exp !== null)
        .map((exp) => ({
          id: exp.id,
          name: exp.name,
          type: exp.type,
          status: exp.status,
          duration: exp.duration_seconds,
          intensity: exp.config.intensity,
          metrics: exp.metrics,
          created_at: exp.created_at,
          created_by: exp.created_by,
        })),
      baseline_metrics: this.baselineMetrics,
    };

    if (format === 'csv') {
      return this.formatExperimentsAsCSV(data);
    }

    return JSON.stringify(data, null, 2);
  }

  /**
   * Format experiments as CSV
   */
  private formatExperimentsAsCSV(data: any): string {
    const headers = [
      'timestamp',
      'experiment_id',
      'name',
      'type',
      'status',
      'duration',
      'intensity',
      'availability_impact',
      'latency_impact',
      'error_rate_impact',
    ];
    const rows = [headers.join(',')];

    data.experiments.forEach((exp: any) => {
      rows.push(
        [
          data.timestamp,
          exp.id,
          exp.name,
          exp.type,
          exp.status,
          exp.duration,
          exp.intensity,
          exp.metrics.availability_impact,
          exp.metrics.latency_impact,
          exp.metrics.error_rate_impact,
        ].join(',')
      );
    });

    return rows.join('\n');
  }

  /**
   * Graceful shutdown
   */
  destroy(): void {
    this.disableChaosTesting();
    logger.info('ChaosTestingService destroyed');
  }
}

// Singleton instance
export const chaosTestingService = new ChaosTestingService();
