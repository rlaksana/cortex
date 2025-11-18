/**
 * Multi-Tenant Services Module
 *
 * Comprehensive multi-tenant isolation, governance, and management services
 * for ensuring fair resource allocation, security, and compliance in shared
 * environments.
 *
 * Services:
 * - TenantIsolationService: Core isolation and resource management
 * - TenantGovernanceService: Governance and compliance procedures
 * - TenantPurgeService: Data cleanup and GDPR compliance
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

export {
  // Service factory functions
  createTenantGovernanceService,
  getTenantGovernanceService,
  // Governance service
  TenantGovernanceService,
} from './tenant-governance-service.js';
export type {
  DEFAULT_TENANT_CONFIG,
  LoadTestResult,
  LoadTestScenario,
  TenantAlert,
  // Configuration and types
  TenantConfig,
  TenantMetrics,
} from './tenant-isolation-service.js';
export {
  // Service factory functions
  createTenantIsolationService,
  getTenantIsolationService,
  MultiTenantLoadTestFramework,
  ResourceAllocationManager,
  TenantCircuitBreaker,
  // Core isolation service
  TenantIsolationService,
  TenantMonitoringService,
  TenantRateLimiter,
} from './tenant-isolation-service.js';
export type {
  TenantPurgeAuditLog,
  // Purge types
  TenantPurgeConfig,
  TenantPurgeExecution,
  TenantPurgePlan,
} from './tenant-purge.service.js';
export {
  // Service factory functions
  createTenantPurgeService,
  getTenantPurgeService,
  // Purge service
  TenantPurgeService,
} from './tenant-purge.service.js';

// === Module Information ===

export const TENANT_SERVICES_INFO = {
  version: '1.0.0',
  description: 'Multi-tenant isolation, governance, and management services',
  features: [
    'Per-tenant rate limiting and circuit breaker enforcement',
    'Multi-tenant load testing with isolation validation',
    'Resource allocation management and monitoring',
    'Tenant monitoring and alerting system',
    'Multi-tenancy governance and compliance procedures',
    'Tenant onboarding and offboarding workflows',
    'GDPR-compliant data purge and cleanup',
    'Cost allocation and billing integration',
  ],
  supported_service_tiers: ['basic', 'standard', 'premium', 'enterprise'],
  compliance_frameworks: ['GDPR', 'CCPA', 'HIPAA', 'SOX', 'PCI-DSS'],
  isolation_features: [
    'Rate limiting per tenant',
    'Circuit breaker per tenant',
    'Resource quotas per tenant',
    'Network isolation',
    'Data isolation',
    'Monitoring isolation',
  ],
  monitoring_capabilities: [
    'Per-tenant health monitoring',
    'Resource usage tracking',
    'Performance metrics',
    'Alert management',
    'Compliance reporting',
    'Cost tracking',
  ],
};

// Note: Default export removed as individual services don't have default exports
// Use named exports instead
