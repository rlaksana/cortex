# Multi-Tenant Isolation and Governance Guide

## Overview

This guide provides comprehensive documentation for the multi-tenant isolation and governance system implemented in Cortex MCP Server. The system ensures fair resource allocation, security, compliance, and proper isolation between tenants in shared environments.

## Architecture

### Core Components

1. **TenantIsolationService**: Core service managing tenant isolation, rate limiting, circuit breakers, and resource allocation
2. **TenantGovernanceService**: Handles tenant lifecycle, compliance, and governance procedures
3. **TenantPurgeService**: Manages data cleanup and GDPR-compliant tenant removal
4. **MultiTenantLoadTestFramework**: Validates tenant isolation and detects noisy neighbor problems

### Key Features

- **Per-tenant rate limiting** with configurable limits and burst capacity
- **Circuit breaker protection** with failure thresholds and recovery mechanisms
- **Resource quota management** for CPU, memory, database connections, and storage
- **Real-time monitoring** and alerting per tenant
- **Comprehensive governance** with onboarding/offboarding workflows
- **GDPR-compliant data management** and purge procedures
- **Load testing framework** for isolation validation

## Quick Start

### 1. Initialize Services

```typescript
import { createTenantIsolationService } from './src/services/tenant/index.js';
import { createTenantGovernanceService } from './src/services/tenant/index.js';
import { createTenantPurgeService } from './src/services/tenant/index.js';
import { QdrantAdapter } from './src/db/adapters/qdrant-adapter.js';

// Initialize vector adapter
const vectorAdapter = new QdrantAdapter({
  url: process.env.QDRANT_URL,
  apiKey: process.env.QDRANT_API_KEY,
  collectionName: 'cortex_memory',
});

// Create services
const isolationService = createTenantIsolationService(vectorAdapter);
const governanceService = createTenantGovernanceService();
const purgeService = createTenantPurgeService(vectorAdapter);
```

### 2. Register a Tenant

```typescript
const tenantConfig = {
  tenant_id: 'tenant-001',
  tenant_name: 'Example Corporation',
  organization_id: 'org-001',
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
      environment: 'production',
      department: 'engineering',
    },
    service_tier: 'standard',
  },
  status: 'active',
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

await isolationService.registerTenant(tenantConfig);
```

### 3. Check Requests

```typescript
// Check if request is allowed
const result = await isolationService.checkRequest('tenant-001', 'memory_store');

if (result.allowed) {
  // Process request
  try {
    // ... your business logic ...

    // Record successful request
    await isolationService.recordSuccess('tenant-001', 150); // response time in ms
  } catch (error) {
    // Record failed request
    await isolationService.recordFailure('tenant-001', error);
  }
} else {
  console.log(`Request blocked: ${result.reason}`);
}
```

## Configuration

### Service Tiers

The system supports four service tiers with different resource allocations:

#### Basic Tier
- **Rate Limits**: 50 RPS, 75 burst capacity
- **Resources**: 5% CPU, 256MB RAM, 3 DB connections
- **Storage**: 1,000 vectors, 5 Mbps bandwidth
- **Monitoring**: 60-second intervals, 7-day retention

#### Standard Tier
- **Rate Limits**: 100 RPS, 150 burst capacity
- **Resources**: 10% CPU, 512MB RAM, 5 DB connections
- **Storage**: 10,000 vectors, 10 Mbps bandwidth
- **Monitoring**: 30-second intervals, 30-day retention

#### Premium Tier
- **Rate Limits**: 500 RPS, 750 burst capacity
- **Resources**: 25% CPU, 2GB RAM, 15 DB connections
- **Storage**: 100,000 vectors, 50 Mbps bandwidth
- **Monitoring**: 15-second intervals, 90-day retention

#### Enterprise Tier
- **Rate Limits**: 2,000 RPS, 3,000 burst capacity
- **Resources**: 50% CPU, 8GB RAM, 50 DB connections
- **Storage**: 1,000,000 vectors, 200 Mbps bandwidth
- **Monitoring**: 5-second intervals, 365-day retention

### Rate Limiting Configuration

```typescript
const rateLimits = {
  requests_per_second: 100,    // Base rate limit
  burst_capacity: 150,         // Maximum burst capacity
  window_ms: 1000,             // Time window in milliseconds
  tool_limits: {
    memory_store: {
      requests_per_second: 50,
      burst_capacity: 75,
    },
    memory_find: {
      requests_per_second: 150,
      burst_capacity: 200,
    },
  },
};
```

### Circuit Breaker Configuration

```typescript
const circuitBreaker = {
  failure_threshold: 5,        // Failures before opening circuit
  recovery_timeout_ms: 60000,  // Time to wait before trying again
  half_open_max_requests: 3,   // Max requests in half-open state
  success_threshold: 3,        // Successes to close circuit
  monitoring_period_ms: 300000, // Period for failure counting
};
```

### Resource Quotas

```typescript
const resourceQuotas = {
  cpu_limit_percent: 10,           // Maximum CPU usage percentage
  memory_limit_mb: 512,            // Maximum memory in MB
  db_connection_pool_size: 5,      // Database connection pool size
  vector_storage_quota: 10000,     // Maximum vector storage count
  network_bandwidth_mbps: 10,      // Network bandwidth limit
  concurrent_requests_limit: 50,   // Maximum concurrent requests
};
```

## Monitoring and Alerting

### Tenant Metrics

The system tracks comprehensive metrics per tenant:

```typescript
const metrics = await isolationService.getRateLimitMetrics('tenant-001');
console.log({
  requests_per_second: metrics.requests_per_second,
  requests_blocked: metrics.requests_blocked,
  remaining_capacity: metrics.remaining_capacity,
});
```

### Health Monitoring

```typescript
// Get resource usage
const resourceUsage = await isolationService.getResourceUsage('tenant-001');
console.log({
  cpu_usage_percent: resourceUsage.cpu_usage_percent,
  memory_usage_percent: resourceUsage.memory_usage_percent,
  db_connections_active: resourceUsage.db_connections_active,
});

// Get circuit breaker status
const circuitBreakerMetrics = await isolationService.getCircuitBreakerMetrics('tenant-001');
console.log({
  state: circuitBreakerMetrics.state,
  failure_count: circuitBreakerMetrics.failure_count,
  success_count: circuitBreakerMetrics.success_count,
});
```

### Alert Management

```typescript
// Get active alerts for a tenant
const alerts = isolationService.getActiveAlerts('tenant-001');
alerts.forEach(alert => {
  console.log(`Alert: ${alert.title} - ${alert.description}`);
  console.log(`Severity: ${alert.severity}`);
  console.log(`Current value: ${alert.threshold_info.current_value}`);
  console.log(`Threshold: ${alert.threshold_info.threshold}`);
});
```

## Governance Workflows

### Tenant Onboarding

1. **Submit Onboarding Request**

```typescript
const requestId = await governanceService.submitOnboardingRequest({
  requester: {
    user_id: 'admin-001',
    email: 'admin@example.com',
    organization_id: 'org-001',
    role: 'admin',
  },
  tenant_info: {
    tenant_name: 'New Company',
    organization_name: 'New Company Inc',
    organization_domain: 'newcompany.com',
    business_category: 'technology',
    expected_users: 100,
    expected_volume: 'medium',
    service_tier: 'standard',
  },
  requirements: {
    compliance_frameworks: ['GDPR', 'CCPA'],
    data_residency: ['US', 'EU'],
    integration_requirements: ['api', 'webhook'],
    custom_features: ['advanced_analytics'],
    sla_requirements: {
      uptime_percentage: 99.9,
      response_time_ms: 500,
      support_level: 'business',
    },
  },
});
```

2. **Review and Approve Request**

```typescript
await governanceService.reviewOnboardingRequest(requestId, {
  reviewed_by: 'reviewer-001',
  approved: true,
  notes: 'Approved for standard tier with custom features',
  conditions: ['Complete security review within 30 days'],
});
```

3. **Provisioning**

The system automatically provisions the tenant with:
- Generated tenant ID and credentials
- Configuration based on service tier
- Resource allocations
- Monitoring setup
- Compliance tracking

### Tenant Offboarding

1. **Submit Offboarding Request**

```typescript
const offboardingRequestId = await governanceService.submitOffboardingRequest({
  tenant_id: 'tenant-001',
  tenant_name: 'Old Company',
  requester: {
    user_id: 'admin-001',
    email: 'admin@example.com',
    role: 'admin',
  },
  reason: {
    category: 'voluntary',
    description: 'Contract termination',
    requested_effective_date: '2024-12-31T00:00:00Z',
  },
  data_handling: {
    export_required: true,
    export_destination: 'secure@company.com',
    retention_period_days: 30,
    compliance_requirements: ['GDPR'],
  },
});
```

2. **Review and Execute**

```typescript
await governanceService.reviewOffboardingRequest(offboardingRequestId, {
  reviewed_by: 'reviewer-001',
  approved: true,
  notes: 'Approved for voluntary offboarding',
});

// The system will execute the offboarding plan:
// 1. Create data backup
// 2. Export data if required
// 3. Revoke access credentials
// 4. Deactivate services
// 5. Schedule data cleanup after retention period
```

### Compliance Reporting

```typescript
// Generate compliance report
const reportId = await governanceService.generateComplianceReport(
  'tenant-001',
  'Example Corporation',
  {
    start_date: '2024-01-01T00:00:00Z',
    end_date: '2024-01-31T23:59:59Z',
  }
);

const report = governanceService.getComplianceReport(reportId);
console.log(`Compliance Score: ${report.frameworks[0].compliance_percentage}%`);
```

### Cost Allocation

```typescript
// Generate cost allocation report
const allocationId = await governanceService.generateCostAllocation(
  'tenant-001',
  'Example Corporation',
  {
    start_date: '2024-01-01T00:00:00Z',
    end_date: '2024-01-31T23:59:59Z',
  }
);

const allocation = governanceService.getCostAllocation(allocationId);
console.log(`Total Cost: $${allocation.billing_info.total} ${allocation.billing_info.currency}`);
```

## Load Testing and Isolation Validation

### Multi-Tenant Load Testing

```typescript
const loadTestScenario = {
  scenario_id: 'isolation-test-001',
  name: 'Tenant Isolation Validation',
  description: 'Test isolation between multiple tenants under load',
  config: {
    duration_seconds: 300,          // 5 minutes
    concurrent_tenants: 10,        // 10 tenants
    requests_per_second_per_tenant: 50,
    payload_size_bytes: 1024,
    test_patterns: [
      { pattern: 'memory_store', weight: 0.6 },
      { pattern: 'memory_find', weight: 0.4 },
    ],
  },
  isolation_validation: {
    isolation_metrics: ['throughput', 'response_time', 'cpu_usage', 'memory_usage'],
    acceptable_variance_percent: 20,
    noisy_neighbor_threshold_percent: 30,
  },
  success_criteria: {
    max_error_rate_percent: 2,
    min_throughput_per_tenant: 45,
    max_response_time_p95_ms: 800,
    max_resource_variance_percent: 15,
  },
};

const results = await isolationService.executeLoadTest(loadTestScenario);

// Analyze results
results.forEach(result => {
  console.log(`Tenant ${result.tenant_id}:`);
  console.log(`  Status: ${result.status}`);
  console.log(`  Throughput: ${result.performance.throughput_requests_per_second} RPS`);
  console.log(`  P95 Response Time: ${result.performance.p95_response_time_ms}ms`);
  console.log(`  Isolation Score: ${result.isolation_validation.isolation_score}%`);
  console.log(`  Noisy Neighbor Detected: ${result.isolation_validation.noisy_neighbor_detected}`);
});
```

### Isolation Validation Results

The load testing framework provides:

- **Isolation Score**: 0-100 score indicating how well tenants are isolated
- **Cross-Tenant Impact Detection**: Identifies when one tenant affects others
- **Noisy Neighbor Detection**: Identifies resource-hogging tenants
- **Resource Variance Analysis**: Measures performance variance between tenants
- **Comprehensive Metrics**: Performance, resource usage, and error tracking

## Data Management and Purge

### GDPR-Compliant Data Purge

```typescript
// Create purge plan
const purgePlan = await purgeService.createPurgePlan('tenant-001', {
  tenant_name: 'Example Corporation',
  organization_id: 'org-001',
  purge_strategy: 'hard_delete',
  scope_filters: {
    project: 'tenant-001',
  },
});

console.log(`Estimated items to purge: ${purgePlan.scope_analysis.total_items}`);
console.log(`Estimated duration: ${purgePlan.scope_analysis.estimated_duration_minutes} minutes`);

// Execute purge (with dry-run for safety)
const execution = await purgeService.executeTenantPurge(purgePlan.plan_id, {
  dry_run: true,                    // Set to false for actual purge
  create_backup: true,
  enable_verification: true,
  confirmation_token: 'user-confirmed-token',
});

console.log(`Purge Status: ${execution.status}`);
console.log(`Items Processed: ${execution.progress.items_processed}`);
console.log(`Items Deleted: ${execution.progress.items_deleted}`);

// Verify compliance
if (execution.compliance_certificate) {
  console.log(`GDPR Compliant: ${execution.compliance_certificate.gdpr_compliant}`);
  console.log(`Certificate ID: ${execution.compliance_certificate.certificate_id}`);
}
```

### Purge Strategies

1. **Hard Delete**: Permanent removal of all data
2. **Soft Delete**: Mark data as deleted but retain for recovery
3. **Anonymize**: Remove personally identifiable information while preserving data structure

### Safety Features

- **Confirmation Requirements**: Prevents accidental data loss
- **Backup Creation**: Automatic backup before purge
- **Verification Process**: Ensures complete data removal
- **Audit Logging**: Complete audit trail for compliance
- **Rollback Capability**: Emergency recovery options

## Best Practices

### 1. Resource Planning

- **Start with appropriate service tier** based on expected usage
- **Monitor resource usage** regularly and adjust quotas as needed
- **Set conservative alert thresholds** to catch issues early
- **Plan for growth** with scalable configurations

### 2. Rate Limiting

- **Configure realistic rate limits** based on usage patterns
- **Use tool-specific limits** for more granular control
- **Monitor rate limit metrics** to identify optimization opportunities
- **Adjust burst capacity** to handle traffic spikes

### 3. Circuit Breaker Configuration

- **Set appropriate failure thresholds** based on error tolerance
- **Configure reasonable recovery timeouts** to allow system recovery
- **Monitor circuit breaker states** to identify systemic issues
- **Use half-open state carefully** to prevent cascading failures

### 4. Monitoring and Alerting

- **Enable comprehensive monitoring** for all critical metrics
- **Configure alert thresholds** based on SLA requirements
- **Regularly review alert patterns** to identify trends
- **Integrate with external monitoring systems** for comprehensive visibility

### 5. Governance

- **Follow standardized onboarding procedures** for all tenants
- **Maintain complete audit trails** for compliance
- **Regular compliance assessments** to ensure adherence
- **Document all configuration changes** and their rationale

### 6. Security

- **Implement proper access controls** for tenant management
- **Regular security reviews** of tenant configurations
- **Encrypt sensitive data** both at rest and in transit
- **Follow principle of least privilege** for all operations

## Troubleshooting

### Common Issues

#### 1. Rate Limit Exceeded

**Symptoms**: Requests being blocked with "Rate limit exceeded" message

**Solutions**:
- Check current rate limit metrics
- Increase rate limits if appropriate
- Optimize request patterns
- Implement client-side throttling

#### 2. Circuit Breaker Open

**Symptoms**: Requests being blocked with "Circuit breaker is open" message

**Solutions**:
- Check circuit breaker metrics
- Identify root cause of failures
- Wait for recovery timeout
- Implement retry logic with exponential backoff

#### 3. Resource Quota Exceeded

**Symptoms**: Requests being blocked with "Resource quota exceeded" message

**Solutions**:
- Check current resource usage
- Optimize resource consumption
- Increase quotas if justified
- Implement resource usage monitoring

#### 4. Tenant Isolation Issues

**Symptoms**: Performance degradation affecting multiple tenants

**Solutions**:
- Run load testing to identify isolation issues
- Check for noisy neighbor problems
- Review resource allocation configuration
- Implement stricter isolation policies

### Debugging Tools

```typescript
// Get detailed tenant status
const status = isolationService.getStatus();
console.log('Service Status:', status);

// Get specific tenant metrics
const metrics = await isolationService.getRateLimitMetrics('tenant-001');
console.log('Rate Limit Metrics:', metrics);

// Get active alerts
const alerts = isolationService.getActiveAlerts('tenant-001');
console.log('Active Alerts:', alerts);

// Get performance metrics
const performance = await isolationService.getPerformanceMetrics('tenant-001');
console.log('Performance Metrics:', performance);
```

## API Reference

### TenantIsolationService

#### Methods

- `registerTenant(config: TenantConfig): Promise<void>`
- `unregisterTenant(tenantId: string): Promise<void>`
- `checkRequest(tenantId: string, toolName?: string): Promise<RequestCheckResult>`
- `recordSuccess(tenantId: string, responseTimeMs: number): Promise<void>`
- `recordFailure(tenantId: string, error: Error): Promise<void>`
- `getRateLimitMetrics(tenantId: string): Promise<RateLimitMetrics>`
- `getCircuitBreakerMetrics(tenantId: string): Promise<CircuitBreakerMetrics>`
- `getResourceUsage(tenantId: string): Promise<ResourceUsage>`
- `executeLoadTest(scenario: LoadTestScenario): Promise<LoadTestResult[]>`

### TenantGovernanceService

#### Methods

- `submitOnboardingRequest(request: OnboardingRequest): Promise<string>`
- `reviewOnboardingRequest(requestId: string, review: Review): Promise<void>`
- `submitOffboardingRequest(request: OffboardingRequest): Promise<string>`
- `reviewOffboardingRequest(requestId: string, review: Review): Promise<void>`
- `generateComplianceReport(tenantId: string, tenantName: string, period: DateRange): Promise<string>`
- `generateCostAllocation(tenantId: string, tenantName: string, period: DateRange): Promise<string>`

### TenantPurgeService

#### Methods

- `createPurgePlan(tenantId: string, options?: PurgeOptions): Promise<PurgePlan>`
- `executeTenantPurge(planId: string, options?: ExecutionOptions): Promise<PurgeExecution>`
- `getPurgeHistory(limit?: number): PurgeExecution[]`
- `getAuditLogs(limit?: number): PurgeAuditLog[]`

## Support and Contributing

For support, questions, or contributions to the multi-tenant isolation system:

1. **Documentation**: Refer to this guide and API documentation
2. **Issues**: Report bugs or request features through the issue tracker
3. **Contributions**: Follow the contribution guidelines for submitting changes
4. **Community**: Join discussions in the community forums

## License

This multi-tenant isolation and governance system is part of the Cortex MCP Server project and follows the same license terms.