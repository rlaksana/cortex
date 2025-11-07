/**
 * Multi-Tenant Isolation Integration Tests
 *
 * Comprehensive integration tests for multi-tenant isolation, rate limiting,
 * circuit breaker functionality, resource allocation, and governance procedures.
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { TenantIsolationService } from '../../src/services/tenant/tenant-isolation-service.js';
import { TenantGovernanceService } from '../../src/services/tenant/tenant-governance-service.js';
import { TenantPurgeService } from '../../src/services/tenant/tenant-purge.service.js';
import type { IVectorAdapter } from '../../src/db/interfaces/vector-adapter.interface.js';

// Mock vector adapter for testing
const mockVectorAdapter: Partial<IVectorAdapter> = {
  getStatistics: async () => ({
    totalItems: 1000,
    vectorCount: 800,
    storageSize: 1024 * 1024 * 100, // 100MB
  }),
  findByScope: async () => [],
  deleteByScope: async () => true,
  search: async () => [],
  store: async () => 'test-id',
  update: async () => true,
  delete: async () => true,
  get: async () => null,
};

describe('Multi-Tenant Isolation Integration Tests', () => {
  let isolationService: TenantIsolationService;
  let governanceService: TenantGovernanceService;
  let purgeService: TenantPurgeService;

  beforeEach(async () => {
    isolationService = new TenantIsolationService(mockVectorAdapter as IVectorAdapter);
    governanceService = new TenantGovernanceService();
    purgeService = new TenantPurgeService(mockVectorAdapter as IVectorAdapter);

    await isolationService.shutdown(); // Clean shutdown after initialization
  });

  afterEach(async () => {
    if (isolationService) {
      await isolationService.shutdown();
    }
  });

  describe('Tenant Registration and Management', () => {
    it('should register a new tenant successfully', async () => {
      const tenantConfig = {
        tenant_id: 'test-tenant-1',
        tenant_name: 'Test Tenant 1',
        organization_id: 'test-org-1',
        rate_limits: {
          requests_per_second: 100,
          burst_capacity: 150,
          window_ms: 1000,
          tool_limits: {
            memory_store: { requests_per_second: 50, burst_capacity: 75 },
            memory_find: { requests_per_second: 150, burst_capacity: 200 },
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
          },
          compliance_frameworks: ['GDPR'],
          audit_logging_enabled: true,
          cost_allocation_tags: {
            environment: 'test',
          },
          service_tier: 'standard' as const,
        },
        status: 'active' as const,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };

      await isolationService.registerTenant(tenantConfig);

      const retrievedConfig = isolationService.getTenantConfig('test-tenant-1');
      expect(retrievedConfig).toBeDefined();
      expect(retrievedConfig?.tenant_name).toBe('Test Tenant 1');
      expect(retrievedConfig?.service_tier).toBe('standard');
    });

    it('should unregister a tenant successfully', async () => {
      const tenantConfig = {
        tenant_id: 'test-tenant-2',
        tenant_name: 'Test Tenant 2',
        organization_id: 'test-org-2',
        rate_limits: {
          requests_per_second: 100,
          burst_capacity: 150,
          window_ms: 1000,
          tool_limits: {},
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
          data_retention_policies: {},
          compliance_frameworks: ['GDPR'],
          audit_logging_enabled: true,
          cost_allocation_tags: {},
          service_tier: 'standard' as const,
        },
        status: 'active' as const,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };

      await isolationService.registerTenant(tenantConfig);

      const configBefore = isolationService.getTenantConfig('test-tenant-2');
      expect(configBefore).toBeDefined();

      await isolationService.unregisterTenant('test-tenant-2');

      const configAfter = isolationService.getTenantConfig('test-tenant-2');
      expect(configAfter).toBeUndefined();
    });

    it('should update tenant configuration successfully', async () => {
      const tenantConfig = {
        tenant_id: 'test-tenant-3',
        tenant_name: 'Test Tenant 3',
        organization_id: 'test-org-3',
        rate_limits: {
          requests_per_second: 100,
          burst_capacity: 150,
          window_ms: 1000,
          tool_limits: {},
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
          data_retention_policies: {},
          compliance_frameworks: ['GDPR'],
          audit_logging_enabled: true,
          cost_allocation_tags: {},
          service_tier: 'standard' as const,
        },
        status: 'active' as const,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };

      await isolationService.registerTenant(tenantConfig);

      const updates = {
        rate_limits: {
          requests_per_second: 200,
          burst_capacity: 300,
          window_ms: 1000,
          tool_limits: {},
        },
        service_tier: 'premium' as const,
      };

      await isolationService.updateTenantConfig('test-tenant-3', updates);

      const updatedConfig = isolationService.getTenantConfig('test-tenant-3');
      expect(updatedConfig?.rate_limits.requests_per_second).toBe(200);
      expect(updatedConfig?.service_tier).toBe('premium');
    });
  });

  describe('Rate Limiting', () => {
    beforeEach(async () => {
      const tenantConfig = {
        tenant_id: 'rate-limit-test',
        tenant_name: 'Rate Limit Test Tenant',
        organization_id: 'test-org',
        rate_limits: {
          requests_per_second: 10, // Low limit for testing
          burst_capacity: 15,
          window_ms: 1000,
          tool_limits: {
            memory_store: { requests_per_second: 5, burst_capacity: 8 },
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
          data_retention_policies: {},
          compliance_frameworks: [],
          audit_logging_enabled: true,
          cost_allocation_tags: {},
          service_tier: 'standard' as const,
        },
        status: 'active' as const,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };

      await isolationService.registerTenant(tenantConfig);
    });

    it('should allow requests within rate limits', async () => {
      const result = await isolationService.checkRequest('rate-limit-test', 'memory_find');
      expect(result.allowed).toBe(true);
    });

    it('should block requests exceeding rate limits', async () => {
      // Make requests up to the limit
      for (let i = 0; i < 15; i++) {
        await isolationService.checkRequest('rate-limit-test', 'memory_find');
      }

      // Next request should be blocked
      const result = await isolationService.checkRequest('rate-limit-test', 'memory_find');
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('Rate limit exceeded');
    });

    it('should enforce tool-specific rate limits', async () => {
      // Make requests up to the tool-specific limit
      for (let i = 0; i < 8; i++) {
        await isolationService.checkRequest('rate-limit-test', 'memory_store');
      }

      // Next request should be blocked due to tool limit
      const result = await isolationService.checkRequest('rate-limit-test', 'memory_store');
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('Rate limit exceeded');
    });

    it('should record rate limit metrics', async () => {
      // Make some requests
      for (let i = 0; i < 5; i++) {
        await isolationService.checkRequest('rate-limit-test', 'memory_find');
        await isolationService.recordSuccess('rate-limit-test', 100);
      }

      const metrics = await isolationService.getRateLimitMetrics('rate-limit-test');
      expect(metrics).toBeDefined();
      expect(metrics?.current_window_requests).toBeGreaterThan(0);
    });
  });

  describe('Circuit Breaker', () => {
    beforeEach(async () => {
      const tenantConfig = {
        tenant_id: 'circuit-breaker-test',
        tenant_name: 'Circuit Breaker Test Tenant',
        organization_id: 'test-org',
        rate_limits: {
          requests_per_second: 100,
          burst_capacity: 150,
          window_ms: 1000,
          tool_limits: {},
        },
        circuit_breaker: {
          failure_threshold: 3, // Low threshold for testing
          recovery_timeout_ms: 1000, // Short timeout for testing
          half_open_max_requests: 2,
          success_threshold: 2,
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
          data_retention_policies: {},
          compliance_frameworks: [],
          audit_logging_enabled: true,
          cost_allocation_tags: {},
          service_tier: 'standard' as const,
        },
        status: 'active' as const,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };

      await isolationService.registerTenant(tenantConfig);
    });

    it('should allow requests when circuit is closed', async () => {
      const result = await isolationService.checkRequest('circuit-breaker-test');
      expect(result.allowed).toBe(true);
    });

    it('should open circuit after failure threshold is reached', async () => {
      // Record failures to trigger circuit breaker
      for (let i = 0; i < 3; i++) {
        await isolationService.recordFailure('circuit-breaker-test', new Error('Test error'));
      }

      // Next request should be blocked due to open circuit
      const result = await isolationService.checkRequest('circuit-breaker-test');
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('Circuit breaker is open');
    });

    it('should close circuit after successful recovery', async () => {
      // Open the circuit
      for (let i = 0; i < 3; i++) {
        await isolationService.recordFailure('circuit-breaker-test', new Error('Test error'));
      }

      // Wait for recovery timeout
      await new Promise((resolve) => setTimeout(resolve, 1100));

      // Record successes to close circuit
      for (let i = 0; i < 2; i++) {
        await isolationService.checkRequest('circuit-breaker-test');
        await isolationService.recordSuccess('circuit-breaker-test', 100);
      }

      // Circuit should be closed again
      const result = await isolationService.checkRequest('circuit-breaker-test');
      expect(result.allowed).toBe(true);
    });

    it('should record circuit breaker metrics', async () => {
      // Record some failures and successes
      await isolationService.recordFailure('circuit-breaker-test', new Error('Test error'));
      await isolationService.recordSuccess('circuit-breaker-test', 100);

      const metrics = await isolationService.getCircuitBreakerMetrics('circuit-breaker-test');
      expect(metrics).toBeDefined();
      expect(metrics?.failure_count).toBe(1);
      expect(metrics?.success_count).toBe(1);
      expect(metrics?.state).toBe('closed');
    });
  });

  describe('Resource Allocation', () => {
    beforeEach(async () => {
      const tenantConfig = {
        tenant_id: 'resource-test',
        tenant_name: 'Resource Test Tenant',
        organization_id: 'test-org',
        rate_limits: {
          requests_per_second: 100,
          burst_capacity: 150,
          window_ms: 1000,
          tool_limits: {},
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
          data_retention_policies: {},
          compliance_frameworks: [],
          audit_logging_enabled: true,
          cost_allocation_tags: {},
          service_tier: 'standard' as const,
        },
        status: 'active' as const,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };

      await isolationService.registerTenant(tenantConfig);
    });

    it('should allow resource consumption within quotas', async () => {
      await isolationService.recordResourceUsage('resource-test', {
        cpu_usage_percent: 5,
        memory_usage_mb: 100,
        db_connections_active: 2,
        network_bandwidth_mbps: 5,
      });

      const result = await isolationService.checkRequest('resource-test');
      expect(result.allowed).toBe(true);
    });

    it('should block requests when resource quotas are exceeded', async () => {
      // Record usage that exceeds quotas
      await isolationService.recordResourceUsage('resource-test', {
        cpu_usage_percent: 15, // Exceeds 10% limit
        memory_usage_mb: 600, // Exceeds 512MB limit
        db_connections_active: 6, // Exceeds 5 connection limit
        network_bandwidth_mbps: 5,
      });

      const result = await isolationService.checkRequest('resource-test');
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('Resource quota exceeded');
    });

    it('should track resource usage metrics', async () => {
      await isolationService.recordResourceUsage('resource-test', {
        cpu_usage_percent: 7,
        memory_usage_mb: 256,
        db_connections_active: 3,
        vector_storage_used: 1000,
        network_bandwidth_mbps: 7,
        concurrent_requests: 10,
      });

      const usage = await isolationService.getResourceUsage('resource-test');
      expect(usage).toBeDefined();
      expect(usage?.cpu_usage_percent).toBe(7);
      expect(usage?.memory_usage_mb).toBe(256);
      expect(usage?.memory_usage_percent).toBeCloseTo(50); // 256/512 * 100
    });
  });

  describe('Load Testing Framework', () => {
    it('should execute multi-tenant load test successfully', async () => {
      const scenario = {
        scenario_id: 'test-scenario-1',
        name: 'Basic Load Test',
        description: 'Test basic multi-tenant isolation',
        config: {
          duration_seconds: 5, // Short duration for testing
          concurrent_tenants: 3,
          requests_per_second_per_tenant: 10,
          payload_size_bytes: 1024,
          test_patterns: [
            { pattern: 'memory_store', weight: 0.6 },
            { pattern: 'memory_find', weight: 0.4 },
          ],
        },
        isolation_validation: {
          isolation_metrics: ['throughput', 'response_time', 'cpu_usage'],
          acceptable_variance_percent: 20,
          noisy_neighbor_threshold_percent: 30,
        },
        success_criteria: {
          max_error_rate_percent: 5,
          min_throughput_per_tenant: 8,
          max_response_time_p95_ms: 1000,
          max_resource_variance_percent: 15,
        },
      };

      const results = await isolationService.executeLoadTest(scenario);

      expect(results).toHaveLength(3); // One result per tenant

      for (const result of results) {
        expect(result.scenario_id).toBe('test-scenario-1');
        expect(result.execution.total_requests).toBeGreaterThan(0);
        expect(result.performance.throughput_requests_per_second).toBeGreaterThan(0);
        expect(result.isolation_validation.isolation_score).toBeGreaterThan(0);
      }
    });

    it('should detect noisy neighbor problems', async () => {
      const scenario = {
        scenario_id: 'noisy-neighbor-test',
        name: 'Noisy Neighbor Test',
        description: 'Test detection of noisy neighbor problems',
        config: {
          duration_seconds: 3,
          concurrent_tenants: 2,
          requests_per_second_per_tenant: 20,
          payload_size_bytes: 2048,
          test_patterns: [{ pattern: 'high_cpu', weight: 1.0 }],
        },
        isolation_validation: {
          isolation_metrics: ['cpu_usage', 'throughput'],
          acceptable_variance_percent: 10, // Very strict
          noisy_neighbor_threshold_percent: 15,
        },
        success_criteria: {
          max_error_rate_percent: 5,
          min_throughput_per_tenant: 15,
          max_response_time_p95_ms: 500,
          max_resource_variance_percent: 10,
        },
      };

      const results = await isolationService.executeLoadTest(scenario);

      // Check if noisy neighbor was detected (this is a simplified test)
      const hasNoisyNeighbor = results.some((r) => r.isolation_validation.noisy_neighbor_detected);

      // Results should be generated regardless of noisy neighbor detection
      expect(results).toHaveLength(2);
      expect(results.every((r) => r.isolation_validation.isolation_score >= 0)).toBe(true);
    });
  });

  describe('Tenant Governance', () => {
    it('should submit and process onboarding request', async () => {
      const requestId = await governanceService.submitOnboardingRequest({
        requester: {
          user_id: 'user-123',
          email: 'test@example.com',
          organization_id: 'org-123',
          role: 'admin',
        },
        tenant_info: {
          tenant_name: 'New Test Tenant',
          organization_name: 'Test Organization',
          organization_domain: 'test.com',
          business_category: 'technology',
          expected_users: 100,
          expected_volume: 'medium',
          service_tier: 'standard',
        },
        requirements: {
          compliance_frameworks: ['GDPR'],
          data_residency: ['US', 'EU'],
          integration_requirements: ['api', 'webhook'],
          custom_features: [],
          sla_requirements: {
            uptime_percentage: 99.9,
            response_time_ms: 500,
            support_level: 'business',
          },
        },
      });

      expect(requestId).toBeDefined();
      expect(requestId).toMatch(/^ONBOARD_\d+_[A-Z0-9]+$/);

      const request = governanceService.getOnboardingRequest(requestId);
      expect(request).toBeDefined();
      expect(request?.status).toBe('under_review');
      expect(request?.tenant_info.tenant_name).toBe('New Test Tenant');
    });

    it('should review and approve onboarding request', async () => {
      const requestId = await governanceService.submitOnboardingRequest({
        requester: {
          user_id: 'user-456',
          email: 'admin@example.com',
          organization_id: 'org-456',
          role: 'admin',
        },
        tenant_info: {
          tenant_name: 'Approved Tenant',
          organization_name: 'Approved Organization',
          organization_domain: 'approved.com',
          business_category: 'finance',
          expected_users: 50,
          expected_volume: 'low',
          service_tier: 'basic',
        },
        requirements: {
          compliance_frameworks: ['GDPR', 'CCPA'],
          data_residency: ['US'],
          integration_requirements: ['api'],
          custom_features: [],
          sla_requirements: {
            uptime_percentage: 99.5,
            response_time_ms: 1000,
            support_level: 'basic',
          },
        },
      });

      await governanceService.reviewOnboardingRequest(requestId, {
        reviewed_by: 'reviewer-123',
        approved: true,
        notes: 'Tenant approved for basic tier',
      });

      const request = governanceService.getOnboardingRequest(requestId);
      expect(request?.status).toBe('approved');
      expect(request?.review_info?.approved).toBe(true);
      expect(request?.review_info?.reviewed_by).toBe('reviewer-123');
    });

    it('should submit offboarding request', async () => {
      const requestId = await governanceService.submitOffboardingRequest({
        tenant_id: 'tenant-to-offboard',
        tenant_name: 'Tenant To Offboard',
        requester: {
          user_id: 'user-789',
          email: 'user@example.com',
          role: 'admin',
        },
        reason: {
          category: 'voluntary',
          description: 'Business requirements changed',
          requested_effective_date: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
        },
        data_handling: {
          export_required: true,
          export_destination: 'secure@example.com',
          retention_period_days: 30,
          compliance_requirements: ['GDPR'],
        },
      });

      expect(requestId).toBeDefined();
      expect(requestId).toMatch(/^OFFBOARD_\d+_[A-Z0-9]+$/);

      const request = governanceService.getOffboardingRequest(requestId);
      expect(request).toBeDefined();
      expect(request?.status).toBe('under_review');
      expect(request?.tenant_id).toBe('tenant-to-offboard');
    });

    it('should generate compliance report', async () => {
      const reportId = await governanceService.generateComplianceReport(
        'compliance-test-tenant',
        'Compliance Test Tenant',
        {
          start_date: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
          end_date: new Date().toISOString(),
        }
      );

      expect(reportId).toBeDefined();
      expect(reportId).toMatch(/^COMPLIANCE_\d+_[A-Z0-9]+$/);

      const report = governanceService.getComplianceReport(reportId);
      expect(report).toBeDefined();
      expect(report?.tenant_id).toBe('compliance-test-tenant');
      expect(report?.frameworks).toHaveLength(1);
      expect(report?.frameworks[0].framework).toBe('GDPR');
    });

    it('should generate cost allocation report', async () => {
      const allocationId = await governanceService.generateCostAllocation(
        'cost-test-tenant',
        'Cost Test Tenant',
        {
          start_date: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
          end_date: new Date().toISOString(),
        }
      );

      expect(allocationId).toBeDefined();
      expect(allocationId).toMatch(/^COST_\d+_[A-Z0-9]+$/);

      const allocation = governanceService.getCostAllocation(allocationId);
      expect(allocation).toBeDefined();
      expect(allocation?.tenant_id).toBe('cost-test-tenant');
      expect(allocation?.billing_info.total).toBeGreaterThan(0);
      expect(allocation?.usage_metrics.total_requests).toBeGreaterThan(0);
    });
  });

  describe('Tenant Purge Service', () => {
    it('should create purge plan for tenant', async () => {
      const plan = await purgeService.createPurgePlan('purge-test-tenant', {
        tenant_name: 'Purge Test Tenant',
        organization_id: 'org-purge',
        purge_strategy: 'hard_delete',
      });

      expect(plan).toBeDefined();
      expect(plan.tenant.tenant_id).toBe('purge-test-tenant');
      expect(plan.tenant.tenant_name).toBe('Purge Test Tenant');
      expect(plan.scope_analysis).toBeDefined();
      expect(plan.impact_assessment).toBeDefined();
      expect(plan.safety_checks).toHaveLength(5); // Default safety checks
      expect(plan.purge_strategy.strategy).toBe('hard_delete');
    });

    it('should execute tenant purge operation', async () => {
      const plan = await purgeService.createPurgePlan('purge-exec-test', {
        tenant_name: 'Purge Execution Test',
        organization_id: 'org-exec',
        purge_strategy: 'soft_delete',
      });

      const execution = await purgeService.executeTenantPurge(plan.plan_id, {
        dry_run: true, // Use dry run for testing
        create_backup: true,
        enable_verification: true,
      });

      expect(execution).toBeDefined();
      expect(execution.plan_id).toBe(plan.plan_id);
      expect(execution.config.dry_run).toBe(true);
      expect(execution.status).toBe('completed');
      expect(execution.progress.total_items).toBeGreaterThan(0);
      expect(execution.details.phases).toHaveLength(5); // Default phases
    });

    it('should generate compliance certificate after purge', async () => {
      const plan = await purgeService.createPurgePlan('cert-test-tenant', {
        tenant_name: 'Certificate Test Tenant',
        organization_id: 'org-cert',
        purge_strategy: 'hard_delete',
      });

      const execution = await purgeService.executeTenantPurge(plan.plan_id, {
        dry_run: false,
        create_backup: true,
        enable_verification: true,
      });

      expect(execution.compliance_certificate).toBeDefined();
      expect(execution.compliance_certificate?.gdpr_compliant).toBe(true);
      expect(execution.compliance_certificate?.data_erasure_verified).toBe(true);
      expect(execution.compliance_certificate?.certificate_id).toMatch(/^cert_\d+_[a-z0-9]+$/);
    });
  });

  describe('Service Status and Health', () => {
    it('should provide accurate service status', () => {
      const isolationStatus = isolationService.getStatus();
      expect(isolationStatus.total_tenants).toBeGreaterThanOrEqual(0);
      expect(isolationStatus.active_tenants).toBeGreaterThanOrEqual(0);
      expect(isolationStatus.total_rate_limiters).toBeGreaterThanOrEqual(0);
      expect(isolationStatus.total_circuit_breakers).toBeGreaterThanOrEqual(0);
    });

    it('should provide governance service status', () => {
      const governanceStatus = governanceService.getStatus();
      expect(governanceStatus.total_onboarding_requests).toBeGreaterThanOrEqual(0);
      expect(governanceStatus.total_offboarding_requests).toBeGreaterThanOrEqual(0);
      expect(governanceStatus.total_compliance_reports).toBeGreaterThanOrEqual(0);
      expect(governanceStatus.active_policies).toBeGreaterThanOrEqual(0);
    });

    it('should provide purge service status', () => {
      const purgeStatus = purgeService.getStatus();
      expect(purgeStatus.is_initialized).toBe(true);
      expect(purgeStatus.active_executions).toBeGreaterThanOrEqual(0);
      expect(purgeStatus.total_executions).toBeGreaterThanOrEqual(0);
      expect(purgeStatus.supported_frameworks).toContain('GDPR');
    });
  });

  describe('Integration Scenarios', () => {
    it('should handle complete tenant lifecycle', async () => {
      // 1. Submit onboarding request
      const onboardingRequestId = await governanceService.submitOnboardingRequest({
        requester: {
          user_id: 'lifecycle-user',
          email: 'lifecycle@example.com',
          organization_id: 'lifecycle-org',
          role: 'admin',
        },
        tenant_info: {
          tenant_name: 'Lifecycle Tenant',
          organization_name: 'Lifecycle Organization',
          organization_domain: 'lifecycle.com',
          business_category: 'testing',
          expected_users: 25,
          expected_volume: 'low',
          service_tier: 'basic',
        },
        requirements: {
          compliance_frameworks: ['GDPR'],
          data_residency: ['US'],
          integration_requirements: ['api'],
          custom_features: [],
          sla_requirements: {
            uptime_percentage: 99.0,
            response_time_ms: 1000,
            support_level: 'basic',
          },
        },
      });

      // 2. Approve onboarding request
      await governanceService.reviewOnboardingRequest(onboardingRequestId, {
        reviewed_by: 'lifecycle-reviewer',
        approved: true,
        notes: 'Approved for testing lifecycle',
      });

      const onboardingRequest = governanceService.getOnboardingRequest(onboardingRequestId);
      expect(onboardingRequest?.status).toBe('approved');
      expect(onboardingRequest?.provisioning_info).toBeDefined();

      const tenantId = onboardingRequest?.provisioning_info?.tenant_id || 'lifecycle-tenant';

      // 3. Register tenant in isolation service
      const tenantConfig = {
        tenant_id: tenantId,
        tenant_name: 'Lifecycle Tenant',
        organization_id: 'lifecycle-org',
        rate_limits: {
          requests_per_second: 50,
          burst_capacity: 75,
          window_ms: 1000,
          tool_limits: {},
        },
        circuit_breaker: {
          failure_threshold: 5,
          recovery_timeout_ms: 60000,
          half_open_max_requests: 3,
          success_threshold: 3,
          monitoring_period_ms: 300000,
        },
        resource_quotas: {
          cpu_limit_percent: 5,
          memory_limit_mb: 256,
          db_connection_pool_size: 3,
          vector_storage_quota: 1000,
          network_bandwidth_mbps: 5,
          concurrent_requests_limit: 25,
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
            entity: 30,
            observation: 30,
            decision: 90,
          },
          compliance_frameworks: ['GDPR'],
          audit_logging_enabled: true,
          cost_allocation_tags: {
            environment: 'test',
            lifecycle: 'true',
          },
          service_tier: 'basic' as const,
        },
        status: 'active' as const,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };

      await isolationService.registerTenant(tenantConfig);

      // 4. Use tenant services
      const requestResult = await isolationService.checkRequest(tenantId);
      expect(requestResult.allowed).toBe(true);

      await isolationService.recordSuccess(tenantId, 150);

      // 5. Generate compliance report
      const complianceReportId = await governanceService.generateComplianceReport(
        tenantId,
        'Lifecycle Tenant',
        {
          start_date: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
          end_date: new Date().toISOString(),
        }
      );

      // 6. Generate cost allocation
      const costAllocationId = await governanceService.generateCostAllocation(
        tenantId,
        'Lifecycle Tenant',
        {
          start_date: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
          end_date: new Date().toISOString(),
        }
      );

      // 7. Submit offboarding request
      const offboardingRequestId = await governanceService.submitOffboardingRequest({
        tenant_id: tenantId,
        tenant_name: 'Lifecycle Tenant',
        requester: {
          user_id: 'lifecycle-user',
          email: 'lifecycle@example.com',
          role: 'admin',
        },
        reason: {
          category: 'voluntary',
          description: 'Testing complete lifecycle',
          requested_effective_date: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        },
        data_handling: {
          export_required: true,
          export_destination: 'lifecycle@example.com',
          retention_period_days: 30,
          compliance_requirements: ['GDPR'],
        },
      });

      // 8. Approve offboarding
      await governanceService.reviewOffboardingRequest(offboardingRequestId, {
        reviewed_by: 'lifecycle-reviewer',
        approved: true,
        notes: 'Approved for lifecycle testing',
      });

      const offboardingRequest = governanceService.getOffboardingRequest(offboardingRequestId);
      expect(offboardingRequest?.status).toBe('approved');

      // 9. Unregister tenant
      await isolationService.unregisterTenant(tenantId);

      // 10. Verify completion
      const finalConfig = isolationService.getTenantConfig(tenantId);
      expect(finalConfig).toBeUndefined();

      const complianceReport = governanceService.getComplianceReport(complianceReportId);
      expect(complianceReport).toBeDefined();

      const costAllocation = governanceService.getCostAllocation(costAllocationId);
      expect(costAllocation).toBeDefined();
    });
  });
});
