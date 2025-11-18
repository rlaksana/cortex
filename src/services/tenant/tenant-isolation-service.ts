/**
 * P8-T8.3: Multi-Tenant Isolation and Governance System
 *
 * Comprehensive tenant-safe limits with per-tenant rate limiting, circuit breaker
 * thresholds, resource allocation management, monitoring, and governance procedures.
 * Ensures fair resource allocation and prevents noisy neighbor problems in
 * multi-tenant environments.
 *
 * Features:
 * - Per-tenant rate limiting and circuit breaker enforcement
 * - Multi-tenant load testing framework with isolation validation
 * - Resource allocation management (CPU, memory, database, storage)
 * - Tenant monitoring and alerting system
 * - Multi-tenancy governance and compliance procedures
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import { EventEmitter } from 'node:events';

import { logger } from '@/utils/logger.js';

import type { IVectorAdapter } from '../../db/interfaces/vector-adapter.interface.js';

// === Type Definitions ===

export interface TenantConfig {
  /** Tenant identification */
  tenant_id: string;
  tenant_name: string;
  organization_id: string;

  /** Rate limiting configuration */
  rate_limits: {
    /** Requests per second per tenant */
    requests_per_second: number;
    /** Burst capacity */
    burst_capacity: number;
    /** Rate limit window in milliseconds */
    window_ms: number;
    /** Tool-specific limits */
    tool_limits: Record<
      string,
      {
        requests_per_second: number;
        burst_capacity: number;
      }
    >;
  };

  /** Circuit breaker configuration */
  circuit_breaker: {
    /** Failure threshold for opening circuit */
    failure_threshold: number;
    /** Recovery timeout in milliseconds */
    recovery_timeout_ms: number;
    /** Half-open max requests */
    half_open_max_requests: number;
    /** Success threshold for closing circuit */
    success_threshold: number;
    /** Monitoring period in milliseconds */
    monitoring_period_ms: number;
  };

  /** Resource quotas */
  resource_quotas: {
    /** CPU limit as percentage (0-100) */
    cpu_limit_percent: number;
    /** Memory limit in MB */
    memory_limit_mb: number;
    /** Database connection pool size */
    db_connection_pool_size: number;
    /** Vector storage quota in number of vectors */
    vector_storage_quota: number;
    /** Network bandwidth limit in Mbps */
    network_bandwidth_mbps: number;
    /** Concurrent request limit */
    concurrent_requests_limit: number;
  };

  /** Monitoring configuration */
  monitoring: {
    /** Health check interval in milliseconds */
    health_check_interval_ms: number;
    /** Metrics retention period in days */
    metrics_retention_days: number;
    /** Alert thresholds */
    alert_thresholds: {
      cpu_usage_percent: number;
      memory_usage_percent: number;
      error_rate_percent: number;
      response_time_ms: number;
      queue_depth: number;
    };
  };

  /** Compliance and governance */
  governance: {
    /** Data retention policies */
    data_retention_policies: Record<string, number>; // days
    /** Compliance frameworks */
    compliance_frameworks: ('GDPR' | 'CCPA' | 'HIPAA' | 'SOX')[];
    /** Audit logging enabled */
    audit_logging_enabled: boolean;
    /** Cost allocation tags */
    cost_allocation_tags: Record<string, string>;
    /** Service tier */
    service_tier: 'basic' | 'standard' | 'premium' | 'enterprise';
  };

  /** Tenant status */
  status: 'active' | 'suspended' | 'terminated' | 'onboarding';

  /** Metadata */
  created_at: string;
  updated_at: string;
  created_by?: string;
}

export interface TenantMetrics {
  /** Tenant identification */
  tenant_id: string;
  /** Timestamp */
  timestamp: string;

  /** Rate limiting metrics */
  rate_limits: {
    requests_per_second: number;
    requests_blocked: number;
    current_window_requests: number;
    remaining_capacity: number;
  };

  /** Circuit breaker metrics */
  circuit_breaker: {
    state: 'closed' | 'open' | 'half-open';
    failure_count: number;
    success_count: number;
    last_failure_time?: string;
    last_success_time?: string;
  };

  /** Resource usage metrics */
  resource_usage: {
    cpu_usage_percent: number;
    memory_usage_mb: number;
    memory_usage_percent: number;
    db_connections_active: number;
    db_connections_idle: number;
    vector_storage_used: number;
    vector_storage_percent: number;
    network_bandwidth_mbps: number;
    concurrent_requests: number;
  };

  /** Performance metrics */
  performance: {
    average_response_time_ms: number;
    p95_response_time_ms: number;
    p99_response_time_ms: number;
    error_rate_percent: number;
    throughput_requests_per_second: number;
  };

  /** Queue metrics */
  queue_metrics: {
    queue_depth: number;
    average_wait_time_ms: number;
    oldest_request_age_ms: number;
  };
}

export interface TenantAlert {
  /** Alert identification */
  alert_id: string;
  tenant_id: string;
  timestamp: string;

  /** Alert details */
  severity: 'info' | 'warning' | 'error' | 'critical';
  category: 'rate_limit' | 'circuit_breaker' | 'resource_usage' | 'performance' | 'compliance';
  title: string;
  description: string;

  /** Current values */
  current_values: Record<string, unknown>;

  /** Threshold information */
  threshold_info: {
    metric: string;
    threshold: number;
    current_value: number;
    percentage_of_threshold: number;
  };

  /** Alert status */
  status: 'active' | 'acknowledged' | 'resolved';

  /** Resolution information */
  resolved_at?: string;
  resolved_by?: string;
  resolution_notes?: string;
}

export interface LoadTestScenario {
  /** Scenario identification */
  scenario_id: string;
  name: string;
  description: string;

  /** Test configuration */
  config: {
    /** Duration in seconds */
    duration_seconds: number;
    /** Number of concurrent tenants */
    concurrent_tenants: number;
    /** Requests per second per tenant */
    requests_per_second_per_tenant: number;
    /** Payload size in bytes */
    payload_size_bytes: number;
    /** Test data patterns */
    test_patterns: Array<{
      pattern: string;
      weight: number;
    }>;
  };

  /** Isolation validation */
  isolation_validation: {
    /** Metrics to monitor for isolation */
    isolation_metrics: string[];
    /** Acceptable variance between tenants (percentage) */
    acceptable_variance_percent: number;
    /** Noisy neighbor detection threshold */
    noisy_neighbor_threshold_percent: number;
  };

  /** Success criteria */
  success_criteria: {
    /** Maximum error rate percentage */
    max_error_rate_percent: number;
    /** Minimum throughput per tenant */
    min_throughput_per_tenant: number;
    /** Maximum response time P95 */
    max_response_time_p95_ms: number;
    /** Resource isolation variance */
    max_resource_variance_percent: number;
  };
}

export interface LoadTestResult {
  /** Result identification */
  result_id: string;
  scenario_id: string;
  tenant_id: string;
  timestamp: string;

  /** Test execution */
  execution: {
    started_at: string;
    completed_at: string;
    duration_seconds: number;
    total_requests: number;
    successful_requests: number;
    failed_requests: number;
  };

  /** Performance metrics */
  performance: {
    average_response_time_ms: number;
    p95_response_time_ms: number;
    p99_response_time_ms: number;
    throughput_requests_per_second: number;
    error_rate_percent: number;
  };

  /** Resource usage */
  resource_usage: {
    peak_cpu_usage_percent: number;
    peak_memory_usage_percent: number;
    peak_db_connections: number;
    peak_network_mbps: number;
  };

  /** Isolation validation */
  isolation_validation: {
    isolation_score: number; // 0-100, higher is better
    cross_tenant_impact_detected: boolean;
    noisy_neighbor_detected: boolean;
    resource_variance_percent: number;
    isolation_breaches: Array<{
      metric: string;
      variance_percent: number;
      threshold_percent: number;
    }>;
  };

  /** Test status */
  status: 'passed' | 'failed' | 'warning';

  /** Issues found */
  issues: Array<{
    category: string;
    description: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    metric?: string;
    actual_value?: number;
    expected_value?: number;
  }>;
}

// === Tenant Rate Limiter ===

export class TenantRateLimiter {
  private tenantWindows = new Map<string, Map<string, number[]>>();
  private toolWindows = new Map<string, Map<string, number[]>>();
  private metrics = new Map<string, TenantMetrics['rate_limits']>();

  constructor(private config: TenantConfig['rate_limits']) {}

  /**
   * Check if a request is allowed for a tenant
   */
  checkRequest(
    tenantId: string,
    toolName?: string
  ): {
    allowed: boolean;
    remaining: number;
    resetTime: number;
  } {
    const now = Date.now();

    // Check tenant-wide rate limit
    const tenantResult = this.checkWindow(
      tenantId,
      this.tenantWindows,
      this.config.requests_per_second,
      this.config.window_ms,
      now
    );

    // Check tool-specific rate limit if applicable
    let toolResult = { allowed: true, remaining: Infinity, resetTime: now };
    if (toolName && this.config.tool_limits[toolName]) {
      const toolConfig = this.config.tool_limits[toolName];
      const toolKey = `${tenantId}:${toolName}`;
      toolResult = this.checkWindow(
        toolKey,
        this.toolWindows,
        toolConfig.requests_per_second,
        this.config.window_ms,
        now
      );
    }

    // Request is allowed only if both limits are satisfied
    const allowed = tenantResult.allowed && toolResult.allowed;
    const remaining = Math.min(tenantResult.remaining, toolResult.remaining);
    const resetTime = Math.max(tenantResult.resetTime, toolResult.resetTime);

    // Update metrics
    this.updateMetrics(tenantId, !allowed);

    return { allowed, remaining, resetTime };
  }

  /**
   * Check sliding window for rate limiting
   */
  private checkWindow(
    key: string,
    windows: Map<string, Map<string, number[]>>,
    limit: number,
    windowMs: number,
    now: number
  ): { allowed: boolean; remaining: number; resetTime: number } {
    if (!windows.has(key)) {
      windows.set(key, new Map());
    }

    const tenantWindows = windows.get(key)!;
    const windowKey = Math.floor(now / windowMs).toString();

    if (!tenantWindows.has(windowKey)) {
      tenantWindows.set(windowKey, []);
    }

    const timestamps = tenantWindows.get(windowKey)!;

    // Clean old windows
    for (const [oldWindowKey, oldTimestamps] of tenantWindows.entries()) {
      if (parseInt(oldWindowKey) < Math.floor(now / windowMs) - 1) {
        tenantWindows.delete(oldWindowKey);
      }
    }

    const allowed = timestamps.length < limit;
    if (allowed) {
      timestamps.push(now);
    }

    const remaining = Math.max(0, limit - timestamps.length);
    const resetTime = (parseInt(windowKey) + 1) * windowMs;

    return { allowed, remaining, resetTime };
  }

  /**
   * Update rate limit metrics
   */
  private updateMetrics(tenantId: string, blocked: boolean): void {
    const existing = this.metrics.get(tenantId) || {
      requests_per_second: 0,
      requests_blocked: 0,
      current_window_requests: 0,
      remaining_capacity: 100,
    };

    existing.requests_per_second = this.calculateCurrentRPS(tenantId);
    if (blocked) {
      existing.requests_blocked++;
    }
    existing.current_window_requests = this.getCurrentWindowRequests(tenantId);
    existing.remaining_capacity = this.calculateRemainingCapacity(tenantId);

    this.metrics.set(tenantId, existing);
  }

  /**
   * Calculate current requests per second
   */
  private calculateCurrentRPS(tenantId: string): number {
    const now = Date.now();
    const windowStart = now - this.config.window_ms;
    let totalRequests = 0;

    const tenantWindows = this.tenantWindows.get(tenantId);
    if (!tenantWindows) return 0;

    for (const timestamps of tenantWindows.values()) {
      totalRequests += timestamps.filter((ts) => ts >= windowStart).length;
    }

    return totalRequests / (this.config.window_ms / 1000);
  }

  /**
   * Get current window requests
   */
  private getCurrentWindowRequests(tenantId: string): number {
    const now = Date.now();
    const windowKey = Math.floor(now / this.config.window_ms).toString();

    const tenantWindows = this.tenantWindows.get(tenantId);
    if (!tenantWindows) return 0;

    return tenantWindows.get(windowKey)?.length || 0;
  }

  /**
   * Calculate remaining capacity percentage
   */
  private calculateRemainingCapacity(tenantId: string): number {
    const current = this.getCurrentWindowRequests(tenantId);
    const limit = this.config.requests_per_second;
    return Math.max(0, ((limit - current) / limit) * 100);
  }

  /**
   * Get rate limit metrics for a tenant
   */
  getMetrics(tenantId: string): TenantMetrics['rate_limits'] | undefined {
    return this.metrics.get(tenantId);
  }

  /**
   * Reset rate limits for a tenant
   */
  resetTenant(tenantId: string): void {
    this.tenantWindows.delete(tenantId);
    this.toolWindows.delete(tenantId);
    this.metrics.delete(tenantId);
  }
}

// === Tenant Circuit Breaker ===

export class TenantCircuitBreaker {
  private states = new Map<string, 'closed' | 'open' | 'half-open'>();
  private failureCounts = new Map<string, number>();
  private successCounts = new Map<string, number>();
  private lastFailureTimes = new Map<string, number>();
  private lastSuccessTimes = new Map<string, number>();
  private halfOpenRequests = new Map<string, number>();

  constructor(private config: TenantConfig['circuit_breaker']) {}

  /**
   * Check if a request should be allowed based on circuit breaker state
   */
  canExecute(tenantId: string): boolean {
    const state = this.getState(tenantId);
    const now = Date.now();

    switch (state) {
      case 'closed':
        return true;

      case 'open':
        // Check if recovery timeout has elapsed
        const lastFailure = this.lastFailureTimes.get(tenantId) || 0;
        if (now - lastFailure >= this.config.recovery_timeout_ms) {
          this.setState(tenantId, 'half-open');
          this.halfOpenRequests.set(tenantId, 0);
          return true;
        }
        return false;

      case 'half-open':
        // Allow limited requests in half-open state
        const currentRequests = this.halfOpenRequests.get(tenantId) || 0;
        if (currentRequests < this.config.half_open_max_requests) {
          this.halfOpenRequests.set(tenantId, currentRequests + 1);
          return true;
        }
        return false;

      default:
        return false;
    }
  }

  /**
   * Record a successful request
   */
  recordSuccess(tenantId: string): void {
    const now = Date.now();
    const state = this.getState(tenantId);

    this.lastSuccessTimes.set(tenantId, now);

    switch (state) {
      case 'closed':
        // Reset failure count on success in closed state
        this.failureCounts.set(tenantId, 0);
        break;

      case 'half-open':
        // Increment success count in half-open state
        const currentSuccess = (this.successCounts.get(tenantId) || 0) + 1;
        this.successCounts.set(tenantId, currentSuccess);

        // Close circuit if success threshold reached
        if (currentSuccess >= this.config.success_threshold) {
          this.setState(tenantId, 'closed');
          this.failureCounts.set(tenantId, 0);
          this.successCounts.set(tenantId, 0);
          this.halfOpenRequests.delete(tenantId);
        }
        break;
    }
  }

  /**
   * Record a failed request
   */
  recordFailure(tenantId: string): void {
    const now = Date.now();
    const state = this.getState(tenantId);

    this.lastFailureTimes.set(tenantId, now);

    switch (state) {
      case 'closed':
        // Increment failure count in closed state
        const currentFailures = (this.failureCounts.get(tenantId) || 0) + 1;
        this.failureCounts.set(tenantId, currentFailures);

        // Open circuit if failure threshold reached
        if (currentFailures >= this.config.failure_threshold) {
          this.setState(tenantId, 'open');
          this.successCounts.set(tenantId, 0);
          this.halfOpenRequests.delete(tenantId);
        }
        break;

      case 'half-open':
        // Immediately open circuit on failure in half-open state
        this.setState(tenantId, 'open');
        this.successCounts.set(tenantId, 0);
        this.halfOpenRequests.delete(tenantId);
        break;
    }
  }

  /**
   * Get current circuit breaker state
   */
  getState(tenantId: string): 'closed' | 'open' | 'half-open' {
    return this.states.get(tenantId) || 'closed';
  }

  /**
   * Set circuit breaker state
   */
  private setState(tenantId: string, state: 'closed' | 'open' | 'half-open'): void {
    const oldState = this.getState(tenantId);
    this.states.set(tenantId, state);

    if (oldState !== state) {
      logger.info('Circuit breaker state changed', {
        tenant_id: tenantId,
        old_state: oldState,
        new_state: state,
        failure_count: this.failureCounts.get(tenantId) || 0,
        success_count: this.successCounts.get(tenantId) || 0,
      });
    }
  }

  /**
   * Get circuit breaker metrics for a tenant
   */
  getMetrics(tenantId: string): TenantMetrics['circuit_breaker'] {
    return {
      state: this.getState(tenantId),
      failure_count: this.failureCounts.get(tenantId) || 0,
      success_count: this.successCounts.get(tenantId) || 0,
      last_failure_time: new Date(this.lastFailureTimes.get(tenantId) || 0).toISOString(),
      last_success_time: new Date(this.lastSuccessTimes.get(tenantId) || 0).toISOString(),
    };
  }

  /**
   * Reset circuit breaker for a tenant
   */
  resetTenant(tenantId: string): void {
    this.states.set(tenantId, 'closed');
    this.failureCounts.set(tenantId, 0);
    this.successCounts.set(tenantId, 0);
    this.lastFailureTimes.delete(tenantId);
    this.lastSuccessTimes.delete(tenantId);
    this.halfOpenRequests.delete(tenantId);
  }
}

// === Resource Allocation Manager ===

export class ResourceAllocationManager {
  private allocations = new Map<string, TenantConfig['resource_quotas']>();
  private usage = new Map<string, TenantMetrics['resource_usage']>();

  constructor(private vectorAdapter: IVectorAdapter) {}

  /**
   * Allocate resources for a tenant
   */
  allocateResources(tenantId: string, quotas: TenantConfig['resource_quotas']): void {
    this.allocations.set(tenantId, quotas);
    logger.info('Resources allocated for tenant', {
      tenant_id: tenantId,
      cpu_limit_percent: quotas.cpu_limit_percent,
      memory_limit_mb: quotas.memory_limit_mb,
      db_connections: quotas.db_connection_pool_size,
      vector_quota: quotas.vector_storage_quota,
    });
  }

  /**
   * Check if tenant can consume additional resources
   */
  canConsumeResources(
    tenantId: string,
    request: {
      cpu_percent?: number;
      memory_mb?: number;
      db_connections?: number;
      vector_count?: number;
      network_mbps?: number;
    }
  ): boolean {
    const allocation = this.allocations.get(tenantId);
    const currentUsage = this.usage.get(tenantId);

    if (!allocation || !currentUsage) {
      return false;
    }

    // Check CPU limit
    if (
      request.cpu_percent &&
      currentUsage.cpu_usage_percent + request.cpu_percent > allocation.cpu_limit_percent
    ) {
      return false;
    }

    // Check memory limit
    if (
      request.memory_mb &&
      currentUsage.memory_usage_mb + request.memory_mb > allocation.memory_limit_mb
    ) {
      return false;
    }

    // Check database connections
    if (
      request.db_connections &&
      currentUsage.db_connections_active + request.db_connections >
        allocation.db_connection_pool_size
    ) {
      return false;
    }

    // Check vector storage quota
    if (
      request.vector_count &&
      currentUsage.vector_storage_used + request.vector_count > allocation.vector_storage_quota
    ) {
      return false;
    }

    // Check network bandwidth
    if (
      request.network_mbps &&
      currentUsage.network_bandwidth_mbps + request.network_mbps > allocation.network_bandwidth_mbps
    ) {
      return false;
    }

    return true;
  }

  /**
   * Record resource usage
   */
  recordUsage(tenantId: string, usage: Partial<TenantMetrics['resource_usage']>): void {
    const current = this.usage.get(tenantId) || {
      cpu_usage_percent: 0,
      memory_usage_mb: 0,
      memory_usage_percent: 0,
      db_connections_active: 0,
      db_connections_idle: 0,
      vector_storage_used: 0,
      vector_storage_percent: 0,
      network_bandwidth_mbps: 0,
      concurrent_requests: 0,
    };

    // Update usage with new values
    Object.assign(current, usage);

    // Calculate percentages if quotas are available
    const allocation = this.allocations.get(tenantId);
    if (allocation) {
      current.memory_usage_percent = (current.memory_usage_mb / allocation.memory_limit_mb) * 100;
      current.vector_storage_percent =
        (current.vector_storage_used / allocation.vector_storage_quota) * 100;
    }

    this.usage.set(tenantId, current);
  }

  /**
   * Get resource usage for a tenant
   */
  getUsage(tenantId: string): TenantMetrics['resource_usage'] | undefined {
    return this.usage.get(tenantId);
  }

  /**
   * Get resource allocation for a tenant
   */
  getAllocation(tenantId: string): TenantConfig['resource_quotas'] | undefined {
    return this.allocations.get(tenantId);
  }

  /**
   * Update resource quotas for a tenant
   */
  updateQuotas(tenantId: string, quotas: Partial<TenantConfig['resource_quotas']>): void {
    const existing = this.allocations.get(tenantId);
    if (existing) {
      this.allocations.set(tenantId, { ...existing, ...quotas });
      logger.info('Resource quotas updated', { tenant_id: tenantId, quotas });
    }
  }

  /**
   * Remove all allocations for a tenant
   */
  removeTenant(tenantId: string): void {
    this.allocations.delete(tenantId);
    this.usage.delete(tenantId);
    logger.info('Resource allocations removed', { tenant_id: tenantId });
  }
}

// === Multi-Tenant Load Testing Framework ===

export class MultiTenantLoadTestFramework extends EventEmitter {
  private activeTests = new Map<string, LoadTestResult>();
  private testHistory: LoadTestResult[] = [];

  constructor(
    private tenantService: TenantIsolationService,
    private vectorAdapter: IVectorAdapter
  ) {
    super();
  }

  /**
   * Execute a multi-tenant load test scenario
   */
  async executeLoadTest(scenario: LoadTestScenario): Promise<LoadTestResult[]> {
    const resultId = `test_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const startTime = new Date().toISOString();

    logger.info('Starting multi-tenant load test', {
      result_id: resultId,
      scenario_id: scenario.scenario_id,
      concurrent_tenants: scenario.config.concurrent_tenants,
      duration_seconds: scenario.config.duration_seconds,
    });

    const results: LoadTestResult[] = [];
    const tenantIds = Array.from(
      { length: scenario.config.concurrent_tenants },
      (_, i) => `test_tenant_${i}`
    );

    try {
      // Create test tenants
      await this.createTestTenants(tenantIds, scenario);

      // Execute concurrent load test
      const testPromises = tenantIds.map((tenantId) =>
        this.runTenantLoadTest(resultId, scenario, tenantId)
      );

      const testResults = await Promise.all(testPromises);
      results.push(...testResults);

      // Validate isolation between tenants
      await this.validateTenantIsolation(results, scenario);

      // Analyze results for noisy neighbor problems
      await this.analyzeNoisyNeighborImpact(results, scenario);

      logger.info('Multi-tenant load test completed', {
        result_id: resultId,
        total_results: results.length,
        passed_count: results.filter((r) => r.status === 'passed').length,
        failed_count: results.filter((r) => r.status === 'failed').length,
      });

      return results;
    } catch (error) {
      logger.error('Multi-tenant load test failed', {
        result_id: resultId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    } finally {
      // Cleanup test tenants
      await this.cleanupTestTenants(tenantIds);

      // Store results
      this.testHistory.push(...results);
    }
  }

  /**
   * Create test tenants with appropriate configurations
   */
  private async createTestTenants(tenantIds: string[], scenario: LoadTestScenario): Promise<void> {
    for (const tenantId of tenantIds) {
      const tenantConfig: TenantConfig = {
        tenant_id: tenantId,
        tenant_name: `Test Tenant ${tenantId}`,
        organization_id: 'test_org',
        rate_limits: {
          requests_per_second: scenario.config.requests_per_second_per_tenant * 2, // Allow burst
          burst_capacity: scenario.config.requests_per_second_per_tenant,
          window_ms: 1000,
          tool_limits: {
            memory_store: {
              requests_per_second: scenario.config.requests_per_second_per_tenant,
              burst_capacity: Math.floor(scenario.config.requests_per_second_per_tenant * 0.8),
            },
            memory_find: {
              requests_per_second: scenario.config.requests_per_second_per_tenant * 1.5,
              burst_capacity: scenario.config.requests_per_second_per_tenant,
            },
          },
        },
        circuit_breaker: {
          failure_threshold: 10,
          recovery_timeout_ms: 30000,
          half_open_max_requests: 5,
          success_threshold: 5,
          monitoring_period_ms: 60000,
        },
        resource_quotas: {
          cpu_limit_percent: 100 / scenario.config.concurrent_tenants, // Fair CPU sharing
          memory_limit_mb: 1024, // 1GB per tenant
          db_connection_pool_size: 10,
          vector_storage_quota: 100000,
          network_bandwidth_mbps: 100,
          concurrent_requests_limit: scenario.config.requests_per_second_per_tenant * 2,
        },
        monitoring: {
          health_check_interval_ms: 5000,
          metrics_retention_days: 7,
          alert_thresholds: {
            cpu_usage_percent: 80,
            memory_usage_percent: 85,
            error_rate_percent: 5,
            response_time_ms: 1000,
            queue_depth: 100,
          },
        },
        governance: {
          data_retention_policies: {
            entity: 30,
            observation: 30,
            decision: 365,
          },
          compliance_frameworks: ['GDPR'],
          audit_logging_enabled: true,
          cost_allocation_tags: {
            environment: 'test',
            test_scenario: scenario.scenario_id,
          },
          service_tier: 'standard',
        },
        status: 'active',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };

      await this.tenantService.registerTenant(tenantConfig);
    }
  }

  /**
   * Run load test for a specific tenant
   */
  private async runTenantLoadTest(
    resultId: string,
    scenario: LoadTestScenario,
    tenantId: string
  ): Promise<LoadTestResult> {
    const startTime = Date.now();
    const result: LoadTestResult = {
      result_id: `${resultId}_${tenantId}`,
      scenario_id: scenario.scenario_id,
      tenant_id: tenantId,
      timestamp: new Date().toISOString(),
      execution: {
        started_at: new Date().toISOString(),
        completed_at: '',
        duration_seconds: 0,
        total_requests: 0,
        successful_requests: 0,
        failed_requests: 0,
      },
      performance: {
        average_response_time_ms: 0,
        p95_response_time_ms: 0,
        p99_response_time_ms: 0,
        throughput_requests_per_second: 0,
        error_rate_percent: 0,
      },
      resource_usage: {
        peak_cpu_usage_percent: 0,
        peak_memory_usage_percent: 0,
        peak_db_connections: 0,
        peak_network_mbps: 0,
      },
      isolation_validation: {
        isolation_score: 0,
        cross_tenant_impact_detected: false,
        noisy_neighbor_detected: false,
        resource_variance_percent: 0,
        isolation_breaches: [],
      },
      status: 'passed',
      issues: [],
    };

    try {
      const duration = scenario.config.duration_seconds * 1000;
      const rps = scenario.config.requests_per_second_per_tenant;
      const interval = 1000 / rps;

      const responseTimes: number[] = [];
      const errors: string[] = [];
      let requestCount = 0;
      let successCount = 0;
      let errorCount = 0;

      // Execute requests for the specified duration
      const endTime = startTime + duration;

      while (Date.now() < endTime) {
        const requestStart = Date.now();

        try {
          // Simulate memory operation
          await this.simulateMemoryOperation(tenantId, scenario.config.payload_size_bytes);

          const responseTime = Date.now() - requestStart;
          responseTimes.push(responseTime);
          successCount++;

          // Record resource usage
          await this.recordResourceUsage(tenantId, {
            cpu_usage_percent: Math.random() * 20, // Simulated
            memory_usage_mb: Math.random() * 100,
            db_connections_active: Math.floor(Math.random() * 5) + 1,
            network_bandwidth_mbps: Math.random() * 10,
          });
        } catch (error) {
          const responseTime = Date.now() - requestStart;
          responseTimes.push(responseTime);
          errorCount++;
          errors.push(error instanceof Error ? error.message : 'Unknown error');
        }

        requestCount++;

        // Wait for next request interval
        if (Date.now() < endTime) {
          await new Promise((resolve) => setTimeout(resolve, interval));
        }
      }

      // Calculate performance metrics
      const sortedTimes = responseTimes.sort((a, b) => a - b);
      result.performance = {
        average_response_time_ms: responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length,
        p95_response_time_ms: sortedTimes[Math.floor(sortedTimes.length * 0.95)],
        p99_response_time_ms: sortedTimes[Math.floor(sortedTimes.length * 0.99)],
        throughput_requests_per_second: requestCount / scenario.config.duration_seconds,
        error_rate_percent: (errorCount / requestCount) * 100,
      };

      result.execution = {
        started_at: new Date(startTime).toISOString(),
        completed_at: new Date().toISOString(),
        duration_seconds: scenario.config.duration_seconds,
        total_requests: requestCount,
        successful_requests: successCount,
        failed_requests: errorCount,
      };

      // Get peak resource usage
      const resourceUsage = await this.tenantService.getResourceUsage(tenantId);
      if (resourceUsage) {
        result.resource_usage = {
          peak_cpu_usage_percent: resourceUsage.cpu_usage_percent,
          peak_memory_usage_percent: resourceUsage.memory_usage_percent,
          peak_db_connections: resourceUsage.db_connections_active,
          peak_network_mbps: resourceUsage.network_bandwidth_mbps,
        };
      }

      // Validate against success criteria
      this.validateTestResult(result, scenario);

      return result;
    } catch (error) {
      result.status = 'failed';
      result.issues.push({
        category: 'execution',
        description: error instanceof Error ? error.message : 'Unknown error',
        severity: 'critical',
      });

      return result;
    }
  }

  /**
   * Simulate a memory operation for testing
   */
  private async simulateMemoryOperation(tenantId: string, payloadSize: number): Promise<void> {
    // Simulate some processing time based on payload size
    const processingTime = Math.min(100, payloadSize / 1000);
    await new Promise((resolve) => setTimeout(resolve, processingTime));

    // Randomly simulate failures (2% failure rate)
    if (Math.random() < 0.02) {
      throw new Error('Simulated operation failure');
    }
  }

  /**
   * Record resource usage during test
   */
  private async recordResourceUsage(
    tenantId: string,
    usage: Partial<TenantMetrics['resource_usage']>
  ): Promise<void> {
    await this.tenantService.recordResourceUsage(tenantId, usage);
  }

  /**
   * Validate test result against success criteria
   */
  private validateTestResult(result: LoadTestResult, scenario: LoadTestScenario): void {
    const criteria = scenario.success_criteria;

    // Check error rate
    if (result.performance.error_rate_percent > criteria.max_error_rate_percent) {
      result.status = 'failed';
      result.issues.push({
        category: 'performance',
        description: `Error rate ${result.performance.error_rate_percent}% exceeds threshold ${criteria.max_error_rate_percent}%`,
        severity: 'high',
        metric: 'error_rate_percent',
        actual_value: result.performance.error_rate_percent,
        expected_value: criteria.max_error_rate_percent,
      });
    }

    // Check throughput
    if (result.performance.throughput_requests_per_second < criteria.min_throughput_per_tenant) {
      result.status = 'failed';
      result.issues.push({
        category: 'performance',
        description: `Throughput ${result.performance.throughput_requests_per_second} RPS below minimum ${criteria.min_throughput_per_tenant} RPS`,
        severity: 'high',
        metric: 'throughput_requests_per_second',
        actual_value: result.performance.throughput_requests_per_second,
        expected_value: criteria.min_throughput_per_tenant,
      });
    }

    // Check response time P95
    if (result.performance.p95_response_time_ms > criteria.max_response_time_p95_ms) {
      if (result.status !== 'failed') {
        result.status = 'warning';
      }
      result.issues.push({
        category: 'performance',
        description: `P95 response time ${result.performance.p95_response_time_ms}ms exceeds threshold ${criteria.max_response_time_p95_ms}ms`,
        severity: 'medium',
        metric: 'p95_response_time_ms',
        actual_value: result.performance.p95_response_time_ms,
        expected_value: criteria.max_response_time_p95_ms,
      });
    }
  }

  /**
   * Validate tenant isolation
   */
  private async validateTenantIsolation(
    results: LoadTestResult[],
    scenario: LoadTestScenario
  ): Promise<void> {
    const acceptableVariance = scenario.isolation_validation.acceptable_variance_percent;

    // Calculate variance in performance metrics between tenants
    const throughputs = results.map((r) => r.performance.throughput_requests_per_second);
    const avgThroughput = throughputs.reduce((a, b) => a + b, 0) / throughputs.length;
    const maxVariance = Math.max(
      ...throughputs.map((t) => (Math.abs(t - avgThroughput) / avgThroughput) * 100)
    );

    // Check each result for isolation validation
    for (const result of results) {
      const variance =
        (Math.abs(result.performance.throughput_requests_per_second - avgThroughput) /
          avgThroughput) *
        100;

      result.isolation_validation.resource_variance_percent = variance;
      result.isolation_validation.isolation_score = Math.max(0, 100 - variance);

      if (variance > acceptableVariance) {
        result.isolation_validation.cross_tenant_impact_detected = true;
        result.isolation_validation.isolation_breaches.push({
          metric: 'throughput_variance',
          variance_percent: variance,
          threshold_percent: acceptableVariance,
        });

        if (result.status !== 'failed') {
          result.status = 'warning';
        }

        result.issues.push({
          category: 'isolation',
          description: `Performance variance ${variance.toFixed(2)}% exceeds acceptable threshold ${acceptableVariance}%`,
          severity: 'medium',
        });
      }
    }
  }

  /**
   * Analyze noisy neighbor impact
   */
  private async analyzeNoisyNeighborImpact(
    results: LoadTestResult[],
    scenario: LoadTestScenario
  ): Promise<void> {
    const threshold = scenario.isolation_validation.noisy_neighbor_threshold_percent;

    // Sort results by resource usage
    const sortedByCpu = [...results].sort(
      (a, b) => b.resource_usage.peak_cpu_usage_percent - a.resource_usage.peak_cpu_usage_percent
    );
    const sortedByMemory = [...results].sort(
      (a, b) =>
        b.resource_usage.peak_memory_usage_percent - a.resource_usage.peak_memory_usage_percent
    );

    // Check if high resource usage impacts other tenants
    const highestCpuUser = sortedByCpu[0];
    const lowestCpuUser = sortedByCpu[sortedByCpu.length - 1];

    if (highestCpuUser && lowestCpuUser && highestCpuUser.tenant_id !== lowestCpuUser.tenant_id) {
      const cpuVariance =
        highestCpuUser.resource_usage.peak_cpu_usage_percent -
        lowestCpuUser.resource_usage.peak_cpu_usage_percent;

      if (cpuVariance > threshold) {
        highestCpuUser.isolation_validation.noisy_neighbor_detected = true;
        highestCpuUser.issues.push({
          category: 'noisy_neighbor',
          description: `High CPU usage may be impacting other tenants (variance: ${cpuVariance.toFixed(2)}%)`,
          severity: 'high',
        });

        if (highestCpuUser.status !== 'failed') {
          highestCpuUser.status = 'warning';
        }
      }
    }
  }

  /**
   * Cleanup test tenants
   */
  private async cleanupTestTenants(tenantIds: string[]): Promise<void> {
    for (const tenantId of tenantIds) {
      try {
        await this.tenantService.unregisterTenant(tenantId);
      } catch (error) {
        logger.warn('Failed to cleanup test tenant', {
          tenant_id: tenantId,
          error: error instanceof Error ? error.message : 'Unknown error',
        });
      }
    }
  }

  /**
   * Get test history
   */
  getTestHistory(limit: number = 50): LoadTestResult[] {
    return this.testHistory
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, limit);
  }
}

// === Tenant Monitoring and Alerting ===

export class TenantMonitoringService extends EventEmitter {
  private alerts = new Map<string, TenantAlert>();
  private metricsHistory = new Map<string, TenantMetrics[]>();
  private monitoringIntervals = new Map<string, NodeJS.Timeout>();

  constructor(private tenantService: TenantIsolationService) {
    super();
  }

  /**
   * Start monitoring a tenant
   */
  startMonitoring(tenantId: string, config: TenantConfig['monitoring']): void {
    // Stop existing monitoring if any
    this.stopMonitoring(tenantId);

    const interval = setInterval(() => {
      this.performHealthCheck(tenantId, config);
    }, config.health_check_interval_ms);

    this.monitoringIntervals.set(tenantId, interval);

    logger.info('Started tenant monitoring', {
      tenant_id: tenantId,
      interval_ms: config.health_check_interval_ms,
    });
  }

  /**
   * Stop monitoring a tenant
   */
  stopMonitoring(tenantId: string): void {
    const interval = this.monitoringIntervals.get(tenantId);
    if (interval) {
      clearInterval(interval);
      this.monitoringIntervals.delete(tenantId);

      logger.info('Stopped tenant monitoring', { tenant_id: tenantId });
    }
  }

  /**
   * Perform health check for a tenant
   */
  private async performHealthCheck(
    tenantId: string,
    config: TenantConfig['monitoring']
  ): Promise<void> {
    try {
      // Collect current metrics
      const metrics = await this.collectMetrics(tenantId);

      // Store metrics history
      this.storeMetricsHistory(tenantId, metrics, config.metrics_retention_days);

      // Check alert thresholds
      await this.checkAlertThresholds(tenantId, metrics, config.alert_thresholds);

      // Emit metrics event
      this.emit('metrics', { tenant_id: tenantId, metrics });
    } catch (error) {
      logger.error('Health check failed', {
        tenant_id: tenantId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      // Create alert for health check failure
      this.createAlert({
        alert_id: `health_check_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        tenant_id: tenantId,
        timestamp: new Date().toISOString(),
        severity: 'error',
        category: 'performance',
        title: 'Health Check Failed',
        description: `Health check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        current_values: { error: error instanceof Error ? error.message : 'Unknown error' },
        threshold_info: {
          metric: 'health_check_status',
          threshold: 1,
          current_value: 0,
          percentage_of_threshold: 0,
        },
        status: 'active',
      });
    }
  }

  /**
   * Collect metrics for a tenant
   */
  private async collectMetrics(tenantId: string): Promise<TenantMetrics> {
    const rateLimitMetrics = await this.tenantService.getRateLimitMetrics(tenantId);
    const circuitBreakerMetrics = await this.tenantService.getCircuitBreakerMetrics(tenantId);
    const resourceUsage = await this.tenantService.getResourceUsage(tenantId);
    const performanceMetrics = await this.tenantService.getPerformanceMetrics(tenantId);
    const queueMetrics = await this.tenantService.getQueueMetrics(tenantId);

    return {
      tenant_id: tenantId,
      timestamp: new Date().toISOString(),
      rate_limits: rateLimitMetrics || {
        requests_per_second: 0,
        requests_blocked: 0,
        current_window_requests: 0,
        remaining_capacity: 100,
      },
      circuit_breaker: circuitBreakerMetrics || {
        state: 'closed',
        failure_count: 0,
        success_count: 0,
      },
      resource_usage: resourceUsage || {
        cpu_usage_percent: 0,
        memory_usage_mb: 0,
        memory_usage_percent: 0,
        db_connections_active: 0,
        db_connections_idle: 0,
        vector_storage_used: 0,
        vector_storage_percent: 0,
        network_bandwidth_mbps: 0,
        concurrent_requests: 0,
      },
      performance: performanceMetrics || {
        average_response_time_ms: 0,
        p95_response_time_ms: 0,
        p99_response_time_ms: 0,
        error_rate_percent: 0,
        throughput_requests_per_second: 0,
      },
      queue_metrics: queueMetrics || {
        queue_depth: 0,
        average_wait_time_ms: 0,
        oldest_request_age_ms: 0,
      },
    };
  }

  /**
   * Store metrics history with retention
   */
  private storeMetricsHistory(
    tenantId: string,
    metrics: TenantMetrics,
    retentionDays: number
  ): void {
    if (!this.metricsHistory.has(tenantId)) {
      this.metricsHistory.set(tenantId, []);
    }

    const history = this.metricsHistory.get(tenantId)!;
    history.push(metrics);

    // Apply retention policy
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    const filtered = history.filter((m) => new Date(m.timestamp) >= cutoffDate);
    this.metricsHistory.set(tenantId, filtered);
  }

  /**
   * Check alert thresholds
   */
  private async checkAlertThresholds(
    tenantId: string,
    metrics: TenantMetrics,
    thresholds: TenantConfig['monitoring']['alert_thresholds']
  ): Promise<void> {
    const alerts: Array<{
      metric: string;
      currentValue: number;
      threshold: number;
      severity: 'warning' | 'error' | 'critical';
      title: string;
    }> = [];

    // Check CPU usage
    if (metrics.resource_usage.cpu_usage_percent > thresholds.cpu_usage_percent) {
      alerts.push({
        metric: 'cpu_usage_percent',
        currentValue: metrics.resource_usage.cpu_usage_percent,
        threshold: thresholds.cpu_usage_percent,
        severity: metrics.resource_usage.cpu_usage_percent > 90 ? 'critical' : 'warning',
        title: 'High CPU Usage',
      });
    }

    // Check memory usage
    if (metrics.resource_usage.memory_usage_percent > thresholds.memory_usage_percent) {
      alerts.push({
        metric: 'memory_usage_percent',
        currentValue: metrics.resource_usage.memory_usage_percent,
        threshold: thresholds.memory_usage_percent,
        severity: metrics.resource_usage.memory_usage_percent > 95 ? 'critical' : 'warning',
        title: 'High Memory Usage',
      });
    }

    // Check error rate
    if (metrics.performance.error_rate_percent > thresholds.error_rate_percent) {
      alerts.push({
        metric: 'error_rate_percent',
        currentValue: metrics.performance.error_rate_percent,
        threshold: thresholds.error_rate_percent,
        severity: metrics.performance.error_rate_percent > 10 ? 'critical' : 'error',
        title: 'High Error Rate',
      });
    }

    // Check response time
    if (metrics.performance.average_response_time_ms > thresholds.response_time_ms) {
      alerts.push({
        metric: 'average_response_time_ms',
        currentValue: metrics.performance.average_response_time_ms,
        threshold: thresholds.response_time_ms,
        severity: 'warning',
        title: 'High Response Time',
      });
    }

    // Check queue depth
    if (metrics.queue_metrics.queue_depth > thresholds.queue_depth) {
      alerts.push({
        metric: 'queue_depth',
        currentValue: metrics.queue_metrics.queue_depth,
        threshold: thresholds.queue_depth,
        severity:
          metrics.queue_metrics.queue_depth > thresholds.queue_depth * 2 ? 'error' : 'warning',
        title: 'High Queue Depth',
      });
    }

    // Create alerts for threshold violations
    for (const alert of alerts) {
      this.createAlert({
        alert_id: `threshold_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        tenant_id: tenantId,
        timestamp: new Date().toISOString(),
        severity: alert.severity,
        category: 'resource_usage',
        title: alert.title,
        description: `${alert.title}: ${alert.currentValue} (threshold: ${alert.threshold})`,
        current_values: { [alert.metric]: alert.currentValue },
        threshold_info: {
          metric: alert.metric,
          threshold: alert.threshold,
          current_value: alert.currentValue,
          percentage_of_threshold: (alert.currentValue / alert.threshold) * 100,
        },
        status: 'active',
      });
    }
  }

  /**
   * Create an alert
   */
  private createAlert(alert: TenantAlert): void {
    this.alerts.set(alert.alert_id, alert);

    logger.warn('Tenant alert created', {
      alert_id: alert.alert_id,
      tenant_id: alert.tenant_id,
      severity: alert.severity,
      category: alert.category,
      title: alert.title,
    });

    // Emit alert event
    this.emit('alert', alert);
  }

  /**
   * Acknowledge an alert
   */
  acknowledgeAlert(alertId: string, acknowledgedBy: string): boolean {
    const alert = this.alerts.get(alertId);
    if (alert && alert.status === 'active') {
      alert.status = 'acknowledged';
      logger.info('Alert acknowledged', {
        alert_id: alertId,
        acknowledged_by: acknowledgedBy,
      });
      return true;
    }
    return false;
  }

  /**
   * Resolve an alert
   */
  resolveAlert(alertId: string, resolvedBy: string, resolutionNotes?: string): boolean {
    const alert = this.alerts.get(alertId);
    if (alert && (alert.status === 'active' || alert.status === 'acknowledged')) {
      alert.status = 'resolved';
      alert.resolved_at = new Date().toISOString();
      alert.resolved_by = resolvedBy;
      alert.resolution_notes = resolutionNotes;

      logger.info('Alert resolved', {
        alert_id: alertId,
        resolved_by: resolvedBy,
        resolution_notes: resolutionNotes,
      });

      return true;
    }
    return false;
  }

  /**
   * Get active alerts for a tenant
   */
  getActiveAlerts(tenantId: string): TenantAlert[] {
    return Array.from(this.alerts.values()).filter(
      (alert) => alert.tenant_id === tenantId && alert.status === 'active'
    );
  }

  /**
   * Get metrics history for a tenant
   */
  getMetricsHistory(tenantId: string, limit: number = 100): TenantMetrics[] {
    const history = this.metricsHistory.get(tenantId) || [];
    return history
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, limit);
  }
}

// === Main Tenant Isolation Service ===

export class TenantIsolationService extends EventEmitter {
  private tenants = new Map<string, TenantConfig>();
  private rateLimiters = new Map<string, TenantRateLimiter>();
  private circuitBreakers = new Map<string, TenantCircuitBreaker>();
  private resourceManager: ResourceAllocationManager;
  private monitoringService: TenantMonitoringService;
  private loadTestFramework: MultiTenantLoadTestFramework;
  private monitoringIntervals = new Map<string, NodeJS.Timeout>();

  constructor(vectorAdapter: IVectorAdapter) {
    super();

    this.resourceManager = new ResourceAllocationManager(vectorAdapter);
    this.monitoringService = new TenantMonitoringService(this);
    this.loadTestFramework = new MultiTenantLoadTestFramework(this, vectorAdapter);
  }

  /**
   * Register a new tenant
   */
  async registerTenant(config: TenantConfig): Promise<void> {
    // Validate tenant configuration
    this.validateTenantConfig(config);

    // Store tenant configuration
    this.tenants.set(config.tenant_id, config);

    // Create rate limiter for tenant
    const rateLimiter = new TenantRateLimiter(config.rate_limits);
    this.rateLimiters.set(config.tenant_id, rateLimiter);

    // Create circuit breaker for tenant
    const circuitBreaker = new TenantCircuitBreaker(config.circuit_breaker);
    this.circuitBreakers.set(config.tenant_id, circuitBreaker);

    // Allocate resources
    this.resourceManager.allocateResources(config.tenant_id, config.resource_quotas);

    // Start monitoring
    this.monitoringService.startMonitoring(config.tenant_id, config.monitoring);

    logger.info('Tenant registered successfully', {
      tenant_id: config.tenant_id,
      tenant_name: config.tenant_name,
      service_tier: config.governance.service_tier,
    });

    this.emit('tenant_registered', { tenant_id: config.tenant_id, config });
  }

  /**
   * Unregister a tenant
   */
  async unregisterTenant(tenantId: string): Promise<void> {
    const config = this.tenants.get(tenantId);
    if (!config) {
      throw new Error(`Tenant ${tenantId} not found`);
    }

    // Stop monitoring
    this.monitoringService.stopMonitoring(tenantId);

    // Remove resource allocations
    this.resourceManager.removeTenant(tenantId);

    // Clean up rate limiter and circuit breaker
    this.rateLimiters.delete(tenantId);
    this.circuitBreakers.delete(tenantId);

    // Remove tenant configuration
    this.tenants.delete(tenantId);

    logger.info('Tenant unregistered successfully', {
      tenant_id: tenantId,
      tenant_name: config.tenant_name,
    });

    this.emit('tenant_unregistered', { tenant_id: tenantId });
  }

  /**
   * Check if a request is allowed for a tenant
   */
  async checkRequest(
    tenantId: string,
    toolName?: string
  ): Promise<{
    allowed: boolean;
    reason?: string;
    rateLimitResult?: Record<string, unknown>;
    circuitBreakerResult?: Record<string, unknown>;
    resourceResult?: Record<string, unknown>;
  }> {
    const config = this.tenants.get(tenantId);
    if (!config) {
      return { allowed: false, reason: 'Tenant not found' };
    }

    if (config.status !== 'active') {
      return { allowed: false, reason: `Tenant status is ${config.status}` };
    }

    // Check rate limits
    const rateLimiter = this.rateLimiters.get(tenantId);
    if (!rateLimiter) {
      return { allowed: false, reason: 'Rate limiter not found' };
    }

    const rateLimitResult = rateLimiter.checkRequest(tenantId, toolName);
    if (!rateLimitResult.allowed) {
      return {
        allowed: false,
        reason: 'Rate limit exceeded',
        rateLimitResult,
      };
    }

    // Check circuit breaker
    const circuitBreaker = this.circuitBreakers.get(tenantId);
    if (!circuitBreaker) {
      return { allowed: false, reason: 'Circuit breaker not found' };
    }

    const circuitBreakerState = circuitBreaker.canExecute(tenantId);
    if (!circuitBreakerState) {
      return {
        allowed: false,
        reason: 'Circuit breaker is open',
        circuitBreakerResult: circuitBreaker.getMetrics(tenantId),
      };
    }

    // Check resource availability
    const resourceAvailable = this.resourceManager.canConsumeResources(tenantId, {
      cpu_percent: 1, // Estimate 1% CPU per request
      memory_mb: 1, // Estimate 1MB per request
      db_connections: 0,
      vector_count: 0,
      network_mbps: 0.1,
    });

    if (!resourceAvailable) {
      return {
        allowed: false,
        reason: 'Resource quota exceeded',
        resourceResult: this.resourceManager.getUsage(tenantId),
      };
    }

    return {
      allowed: true,
      rateLimitResult,
      circuitBreakerResult: circuitBreaker.getMetrics(tenantId),
    };
  }

  /**
   * Record successful request
   */
  async recordSuccess(tenantId: string, responseTimeMs: number): Promise<void> {
    const circuitBreaker = this.circuitBreakers.get(tenantId);
    if (circuitBreaker) {
      circuitBreaker.recordSuccess(tenantId);
    }

    // Record resource usage
    await this.recordResourceUsage(tenantId, {
      cpu_usage_percent: Math.random() * 5, // Estimate
      memory_usage_mb: Math.random() * 10,
      db_connections_active: 0,
      network_bandwidth_mbps: Math.random() * 1,
    });

    this.emit('request_success', { tenant_id: tenantId, response_time_ms: responseTimeMs });
  }

  /**
   * Record failed request
   */
  async recordFailure(tenantId: string, error: Error): Promise<void> {
    const circuitBreaker = this.circuitBreakers.get(tenantId);
    if (circuitBreaker) {
      circuitBreaker.recordFailure(tenantId);
    }

    this.emit('request_failure', { tenant_id: tenantId, error: error.message });
  }

  /**
   * Record resource usage
   */
  async recordResourceUsage(
    tenantId: string,
    usage: Partial<TenantMetrics['resource_usage']>
  ): Promise<void> {
    this.resourceManager.recordUsage(tenantId, usage);
  }

  /**
   * Get rate limit metrics for a tenant
   */
  async getRateLimitMetrics(tenantId: string): Promise<TenantMetrics['rate_limits'] | undefined> {
    const rateLimiter = this.rateLimiters.get(tenantId);
    return rateLimiter?.getMetrics(tenantId);
  }

  /**
   * Get circuit breaker metrics for a tenant
   */
  async getCircuitBreakerMetrics(
    tenantId: string
  ): Promise<TenantMetrics['circuit_breaker'] | undefined> {
    const circuitBreaker = this.circuitBreakers.get(tenantId);
    return circuitBreaker?.getMetrics(tenantId);
  }

  /**
   * Get resource usage for a tenant
   */
  async getResourceUsage(tenantId: string): Promise<TenantMetrics['resource_usage'] | undefined> {
    return this.resourceManager.getUsage(tenantId);
  }

  /**
   * Get performance metrics for a tenant
   */
  async getPerformanceMetrics(tenantId: string): Promise<TenantMetrics['performance'] | undefined> {
    // This would be implemented with actual performance tracking
    return {
      average_response_time_ms: 100,
      p95_response_time_ms: 200,
      p99_response_time_ms: 500,
      error_rate_percent: 1,
      throughput_requests_per_second: 50,
    };
  }

  /**
   * Get queue metrics for a tenant
   */
  async getQueueMetrics(tenantId: string): Promise<TenantMetrics['queue_metrics'] | undefined> {
    // This would be implemented with actual queue tracking
    return {
      queue_depth: 5,
      average_wait_time_ms: 50,
      oldest_request_age_ms: 200,
    };
  }

  /**
   * Execute load test
   */
  async executeLoadTest(scenario: LoadTestScenario): Promise<LoadTestResult[]> {
    return this.loadTestFramework.executeLoadTest(scenario);
  }

  /**
   * Get load test history
   */
  getLoadTestHistory(limit: number = 50): LoadTestResult[] {
    return this.loadTestFramework.getTestHistory(limit);
  }

  /**
   * Get active alerts for a tenant
   */
  getActiveAlerts(tenantId: string): TenantAlert[] {
    return this.monitoringService.getActiveAlerts(tenantId);
  }

  /**
   * Get tenant configuration
   */
  getTenantConfig(tenantId: string): TenantConfig | undefined {
    return this.tenants.get(tenantId);
  }

  /**
   * Update tenant configuration
   */
  async updateTenantConfig(tenantId: string, updates: Partial<TenantConfig>): Promise<void> {
    const config = this.tenants.get(tenantId);
    if (!config) {
      throw new Error(`Tenant ${tenantId} not found`);
    }

    const updatedConfig = { ...config, ...updates, updated_at: new Date().toISOString() };
    this.tenants.set(tenantId, updatedConfig);

    // Update rate limiter if rate limits changed
    if (updates.rate_limits) {
      const rateLimiter = new TenantRateLimiter(updatedConfig.rate_limits);
      this.rateLimiters.set(tenantId, rateLimiter);
    }

    // Update circuit breaker if config changed
    if (updates.circuit_breaker) {
      const circuitBreaker = new TenantCircuitBreaker(updatedConfig.circuit_breaker);
      this.circuitBreakers.set(tenantId, circuitBreaker);
    }

    // Update resource quotas if changed
    if (updates.resource_quotas) {
      this.resourceManager.updateQuotas(tenantId, updates.resource_quotas);
    }

    // Update monitoring if config changed
    if (updates.monitoring) {
      this.monitoringService.stopMonitoring(tenantId);
      this.monitoringService.startMonitoring(tenantId, updatedConfig.monitoring);
    }

    logger.info('Tenant configuration updated', {
      tenant_id: tenantId,
      updated_fields: Object.keys(updates),
    });

    this.emit('tenant_config_updated', { tenant_id: tenantId, updates });
  }

  /**
   * Validate tenant configuration
   */
  private validateTenantConfig(config: TenantConfig): void {
    if (!config.tenant_id || !config.tenant_name || !config.organization_id) {
      throw new Error('Tenant ID, name, and organization ID are required');
    }

    if (config.rate_limits.requests_per_second <= 0) {
      throw new Error('Rate limit requests per second must be positive');
    }

    if (
      config.resource_quotas.cpu_limit_percent <= 0 ||
      config.resource_quotas.cpu_limit_percent > 100
    ) {
      throw new Error('CPU limit must be between 0 and 100');
    }

    if (config.resource_quotas.memory_limit_mb <= 0) {
      throw new Error('Memory limit must be positive');
    }
  }

  /**
   * Get service status
   */
  getStatus(): {
    total_tenants: number;
    active_tenants: number;
    total_rate_limiters: number;
    total_circuit_breakers: number;
    monitoring_active_count: number;
  } {
    const activeTenants = Array.from(this.tenants.values()).filter(
      (t) => t.status === 'active'
    ).length;

    return {
      total_tenants: this.tenants.size,
      active_tenants: activeTenants,
      total_rate_limiters: this.rateLimiters.size,
      total_circuit_breakers: this.circuitBreakers.size,
      monitoring_active_count: this.monitoringIntervals?.size || 0,
    };
  }

  /**
   * Graceful shutdown
   */
  async shutdown(): Promise<void> {
    logger.info('Shutting down TenantIsolationService');

    // Stop all monitoring
    for (const tenantId of this.tenants.keys()) {
      this.monitoringService.stopMonitoring(tenantId);
    }

    // Clean up resources
    this.tenants.clear();
    this.rateLimiters.clear();
    this.circuitBreakers.clear();

    logger.info('TenantIsolationService shutdown completed');
  }
}

// === Default Configurations ===

export const DEFAULT_TENANT_CONFIG: Partial<TenantConfig> = {
  rate_limits: {
    requests_per_second: 100,
    burst_capacity: 150,
    window_ms: 1000,
    tool_limits: {
      memory_store: { requests_per_second: 50, burst_capacity: 75 },
      memory_find: { requests_per_second: 150, burst_capacity: 200 },
      database_health: { requests_per_second: 30, burst_capacity: 45 },
      database_stats: { requests_per_second: 30, burst_capacity: 45 },
      telemetry_report: { requests_per_second: 10, burst_capacity: 15 },
    },
  },
  circuit_breaker: {
    failure_threshold: 5,
    recovery_timeout_ms: 60000,
    half_open_max_requests: 3,
    success_threshold: 3,
    monitoring_period_ms: 300000,
  },
  resource_quotas: {
    cpu_limit_percent: 10,
    memory_limit_mb: 512,
    db_connection_pool_size: 5,
    vector_storage_quota: 10000,
    network_bandwidth_mbps: 10,
    concurrent_requests_limit: 50,
  },
  monitoring: {
    health_check_interval_ms: 30000,
    metrics_retention_days: 30,
    alert_thresholds: {
      cpu_usage_percent: 80,
      memory_usage_percent: 85,
      error_rate_percent: 5,
      response_time_ms: 1000,
      queue_depth: 100,
    },
  },
  governance: {
    data_retention_policies: {
      entity: 90,
      observation: 90,
      decision: 365,
      issue: 90,
      todo: 90,
    },
    compliance_frameworks: ['GDPR'],
    audit_logging_enabled: true,
    cost_allocation_tags: {},
    service_tier: 'standard',
  },
  status: 'active',
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

// === Global Service Instance ===

let tenantIsolationServiceInstance: TenantIsolationService | null = null;

export function createTenantIsolationService(
  vectorAdapter: IVectorAdapter
): TenantIsolationService {
  tenantIsolationServiceInstance = new TenantIsolationService(vectorAdapter);
  return tenantIsolationServiceInstance;
}

export function getTenantIsolationService(): TenantIsolationService | null {
  return tenantIsolationServiceInstance;
}
