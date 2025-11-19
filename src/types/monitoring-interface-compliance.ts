/**
 * Interface Compliance for Complex Monitoring Systems
 *
 * Provides strict interface definitions and compliance checking for monitoring
 * systems to ensure consistent behavior across implementations.
 *
 * Features:
 * - Strict interface definitions with type safety
 * - Compliance checking and validation
 * - Plugin architecture for monitoring providers
 * - Version compatibility management
 * - Runtime interface compliance verification
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import {
  type AlertId,
  type DeploymentId,
  type MetricName,
  type TagKey,
  type TagValue,
  type Timestamp,
} from './branded-types.js';
import {
  type AlertSeverity,
  type MetricCategory,
  type MetricType,
  type TypedMetric,
} from './metrics-types.js';
import type { CanaryHealthConfig, HealthMetricsSnapshot } from '../services/canary/canary-health-monitor.js';

// ============================================================================
// Core Monitoring Interface Definitions
// ============================================================================

/**
 * Core monitoring provider interface
 */
export interface IMonitoringProvider {
  readonly name: string;
  readonly version: string;
  readonly capabilities: MonitoringCapabilities;

  // Lifecycle management
  initialize(config: MonitoringProviderConfig): Promise<void>;
  shutdown(): Promise<void>;
  isHealthy(): Promise<boolean>;

  // Metrics operations
  recordMetric(metric: TypedMetric): Promise<void>;
  getMetrics(query: MetricQuery): Promise<TypedMetric[]>;
  deleteMetrics(criteria: MetricDeletionCriteria): Promise<number>;

  // Alerting operations
  createAlert(alert: AlertDefinition): Promise<AlertId>;
  updateAlert(alertId: AlertId, updates: Partial<AlertDefinition>): Promise<void>;
  deleteAlert(alertId: AlertId): Promise<void>;
  getActiveAlerts(deploymentId?: DeploymentId): Promise<Alert[]>;

  // Health monitoring
  registerHealthMonitor(config: CanaryHealthConfig): Promise<void>;
  getHealthSnapshot(deploymentId: DeploymentId): Promise<HealthMetricsSnapshot | null>;
}

/**
 * Monitoring capabilities descriptor
 */
export interface MonitoringCapabilities {
  // Metric capabilities
  supportedMetricTypes: MetricType[];
  supportedCategories: MetricCategory[];
  maxMetricsPerBatch: number;
  supportsRealTime: boolean;
  supportsHistorical: boolean;

  // Alerting capabilities
  supportsAlerting: boolean;
  maxAlertsPerDeployment: number;
  supportedAlertSeverities: AlertSeverity[];
  supportsEscalation: boolean;

  // Storage capabilities
  retentionPeriodHours: number;
  supportsDataExport: boolean;
  supportedExportFormats: ('json' | 'prometheus' | 'csv' | 'influxdb')[];
  supportsCompression: boolean;

  // Integration capabilities
  supportedIntegrations: string[];
  supportsWebhooks: boolean;
  supportsSlack: boolean;
  supportsEmail: boolean;

  // Performance characteristics
  maxConcurrentRequests: number;
  requestTimeoutMs: number;
  batchProcessingSupported: boolean;
  maxBatchSize: number;
}

/**
 * Monitoring provider configuration
 */
export interface MonitoringProviderConfig {
  endpoint?: string;
  apiKey?: string;
  timeout?: number;
  retryPolicy?: RetryPolicy;
  batchSize?: number;
  compressionEnabled?: boolean;
  customHeaders?: Record<string, string>;
}

/**
 * Retry policy configuration
 */
export interface RetryPolicy {
  maxAttempts: number;
  initialDelayMs: number;
  maxDelayMs: number;
  backoffMultiplier: number;
  retryableErrors: string[];
}

/**
 * Metric query interface
 */
export interface MetricQuery {
  metricNames?: MetricName[];
  metricTypes?: MetricType[];
  categories?: MetricCategory[];
  tags?: Record<TagKey, TagValue>;
  timeRange?: {
    start: Timestamp;
    end: Timestamp;
  };
  aggregation?: MetricAggregation;
  limit?: number;
  offset?: number;
}

/**
 * Metric aggregation specification
 */
export interface MetricAggregation {
  function: 'avg' | 'sum' | 'min' | 'max' | 'count' | 'p50' | 'p95' | 'p99';
  interval: number; // in seconds
  groupBy?: TagKey[];
}

/**
 * Metric deletion criteria
 */
export interface MetricDeletionCriteria {
  olderThan: Timestamp;
  metricNames?: MetricName[];
  tags?: Record<TagKey, TagValue>;
  batchSize?: number;
}

/**
 * Alert definition
 */
export interface AlertDefinition {
  id?: AlertId;
  name: string;
  description: string;
  severity: AlertSeverity;
  condition: AlertCondition;
  actions: AlertAction[];
  enabled: boolean;
  cooldownPeriodMs: number;
  escalationPolicy?: EscalationPolicy;
  metadata?: Record<string, unknown>;
}

/**
 * Alert condition
 */
export interface AlertCondition {
  metricName: MetricName;
  operator: 'gt' | 'gte' | 'lt' | 'lte' | 'eq' | 'ne';
  threshold: number;
  evaluationWindowMs: number;
  consecutiveViolations: number;
  tags?: Record<TagKey, TagValue>;
}

/**
 * Alert action
 */
export interface AlertAction {
  type: 'webhook' | 'slack' | 'email' | 'pagerduty';
  config: Record<string, unknown>;
  enabled: boolean;
  timeoutMs: number;
}

/**
 * Escalation policy
 */
export interface EscalationPolicy {
  levels: EscalationLevel[];
  autoResolve: boolean;
  resolveAfterMs: number;
}

/**
 * Escalation level
 */
export interface EscalationLevel {
  delayMs: number;
  severity: AlertSeverity;
  actions: AlertAction[];
}

/**
 * Alert instance
 */
export interface Alert {
  id: AlertId;
  definitionId: AlertId;
  deploymentId: DeploymentId;
  name: string;
  description: string;
  severity: AlertSeverity;
  state: AlertState;
  triggeredAt: Timestamp;
  acknowledgedAt?: Timestamp;
  resolvedAt?: Timestamp;
  acknowledgedBy?: string;
  resolvedBy?: string;
  metadata: Record<string, unknown>;
}

/**
 * Alert state enumeration
 */
export enum AlertState {
  OK = 'ok',
  WARNING = 'warning',
  CRITICAL = 'critical',
  ACKNOWLEDGED = 'acknowledged',
  RESOLVED = 'resolved',
  SUPPRESSED = 'suppressed',
}

// ============================================================================
// Interface Compliance Checking
// ============================================================================

/**
 * Interface compliance checker
 */
export class MonitoringInterfaceComplianceChecker {
  private static readonly REQUIRED_CAPABILITIES = [
    'supportedMetricTypes',
    'supportedCategories',
    'maxMetricsPerBatch',
    'retentionPeriodHours',
    'maxConcurrentRequests',
    'requestTimeoutMs',
  ] as const;

  /**
   * Check if a provider implements the IMonitoringProvider interface correctly
   */
  static async checkCompliance(provider: IMonitoringProvider): Promise<ComplianceReport> {
    const report: ComplianceReport = {
      providerName: provider.name,
      providerVersion: provider.version,
      overallCompliance: true,
      interfaceCompliance: await this.checkInterfaceCompliance(provider),
      capabilityCompliance: this.checkCapabilityCompliance(provider.capabilities),
      operationalCompliance: await this.checkOperationalCompliance(provider),
      recommendations: [],
      warnings: [],
      errors: [],
    };

    // Update overall compliance
    report.overallCompliance =
      report.interfaceCompliance.isCompliant &&
      report.capabilityCompliance.isCompliant &&
      report.operationalCompliance.isCompliant;

    return report;
  }

  /**
   * Check interface method compliance
   */
  private static async checkInterfaceCompliance(provider: IMonitoringProvider): Promise<InterfaceCompliance> {
    const compliance: InterfaceCompliance = {
      isCompliant: true,
      methods: {},
      errors: [],
    };

    const requiredMethods = [
      'initialize',
      'shutdown',
      'isHealthy',
      'recordMetric',
      'getMetrics',
      'deleteMetrics',
      'createAlert',
      'updateAlert',
      'deleteAlert',
      'getActiveAlerts',
      'registerHealthMonitor',
      'getHealthSnapshot',
    ] as const;

    for (const method of requiredMethods) {
      try {
        const methodExists = typeof (provider as unknown)[method] === 'function';
        compliance.methods[method] = {
          exists: methodExists,
          signature: this.getMethodSignature(provider, method),
          accessible: methodExists,
        };

        if (!methodExists) {
          compliance.isCompliant = false;
          compliance.errors.push(`Required method ${method} is missing`);
        }
      } catch (error) {
        compliance.isCompliant = false;
        compliance.methods[method] = {
          exists: false,
          signature: 'unknown',
          accessible: false,
        };
        compliance.errors.push(`Error checking method ${method}: ${error}`);
      }
    }

    return compliance;
  }

  /**
   * Check capability compliance
   */
  private static checkCapabilityCompliance(capabilities: MonitoringCapabilities): CapabilityCompliance {
    const compliance: CapabilityCompliance = {
      isCompliant: true,
      capabilities: {},
      warnings: [],
    };

    // Check required capabilities
    for (const capability of this.REQUIRED_CAPABILITIES) {
      const hasCapability = capabilities.hasOwnProperty(capability);
      const value = (capabilities as unknown)[capability];

      compliance.capabilities[capability] = {
        present: hasCapability,
        value: value,
        valid: this.validateCapabilityValue(capability, value),
      };

      if (!hasCapability) {
        compliance.isCompliant = false;
        compliance.warnings.push(`Missing required capability: ${capability}`);
      } else if (!this.validateCapabilityValue(capability, value)) {
        compliance.isCompliant = false;
        compliance.warnings.push(`Invalid value for capability ${capability}: ${value}`);
      }
    }

    return compliance;
  }

  /**
   * Check operational compliance
   */
  private static async checkOperationalCompliance(provider: IMonitoringProvider): Promise<OperationalCompliance> {
    const compliance: OperationalCompliance = {
      isCompliant: true,
      healthCheck: false,
      performance: {
        responseTime: 0,
        throughput: 0,
        errorRate: 0,
      },
      errors: [],
    };

    try {
      // Test health check
      const startTime = Date.now();
      compliance.healthCheck = await provider.isHealthy();
      const responseTime = Date.now() - startTime;

      // Performance checks
      if (responseTime > 5000) { // 5 seconds
        compliance.isCompliant = false;
        compliance.errors.push('Health check response time too slow');
      }

      compliance.performance.responseTime = responseTime;

      // Test basic operations (mock operations)
      try {
        const testMetric: TypedMetric = {
          id: 'test-metric',
          name: 'test_metric',
          type: 'counter' as unknown,
          category: 'system' as unknown,
          value: 1,
          timestamp: new Date().toISOString(),
          component: 'compliance-test',
          dimensions: [],
          labels: {},
          quality: {
          accuracy: 1,
          consistency: 1,
          completeness: 1,
          timeliness: 1,
          validity: 1,
          reliability: 1,
          lastValidated: new Date().toISOString(),
        },
          metadata: {},
        };

        const recordStart = Date.now();
        await provider.recordMetric(testMetric);
        compliance.performance.throughput = 1000 / (Date.now() - recordStart); // ops per second
      } catch (error) {
        compliance.isCompliant = false;
        compliance.errors.push(`Metric recording failed: ${error}`);
        compliance.performance.errorRate = 1;
      }

    } catch (error) {
      compliance.isCompliant = false;
      compliance.errors.push(`Operational compliance check failed: ${error}`);
    }

    return compliance;
  }

  /**
   * Get method signature (simplified)
   */
  private static getMethodSignature(provider: IMonitoringProvider, methodName: string): string {
    try {
      const method = (provider as unknown)[methodName];
      if (typeof method !== 'function') {
        return 'not a function';
      }
      return method.toString().substring(0, 100) + '...';
    } catch {
      return 'unknown';
    }
  }

  /**
   * Validate capability value
   */
  private static validateCapabilityValue(capability: string, value: unknown): boolean {
    switch (capability) {
      case 'supportedMetricTypes':
        return Array.isArray(value) && value.length > 0;
      case 'supportedCategories':
        return Array.isArray(value) && value.length > 0;
      case 'maxMetricsPerBatch':
        return typeof value === 'number' && value > 0;
      case 'retentionPeriodHours':
        return typeof value === 'number' && value > 0;
      case 'maxConcurrentRequests':
        return typeof value === 'number' && value > 0;
      case 'requestTimeoutMs':
        return typeof value === 'number' && value > 0;
      default:
        return true;
    }
  }
}

// ============================================================================
// Compliance Report Types
// ============================================================================

/**
 * Comprehensive compliance report
 */
export interface ComplianceReport {
  providerName: string;
  providerVersion: string;
  overallCompliance: boolean;
  interfaceCompliance: InterfaceCompliance;
  capabilityCompliance: CapabilityCompliance;
  operationalCompliance: OperationalCompliance;
  recommendations: string[];
  warnings: string[];
  errors: string[];
}

/**
 * Interface compliance details
 */
export interface InterfaceCompliance {
  isCompliant: boolean;
  methods: Record<string, {
    exists: boolean;
    signature: string;
    accessible: boolean;
  }>;
  errors: string[];
}

/**
 * Capability compliance details
 */
export interface CapabilityCompliance {
  isCompliant: boolean;
  capabilities: Record<string, {
    present: boolean;
    value: unknown;
    valid: boolean;
  }>;
  warnings: string[];
}

/**
 * Operational compliance details
 */
export interface OperationalCompliance {
  isCompliant: boolean;
  healthCheck: boolean;
  performance: {
    responseTime: number;
    throughput: number;
    errorRate: number;
  };
  errors: string[];
}

// ============================================================================
// Monitoring Provider Registry
// ============================================================================

/**
 * Registry for monitoring providers with compliance checking
 */
export class MonitoringProviderRegistry {
  private providers: Map<string, RegisteredProvider> = new Map();
  private complianceCache: Map<string, ComplianceReport> = new Map();
  private cacheTimeoutMs = 300000; // 5 minutes

  /**
   * Register a monitoring provider
   */
  async registerProvider(provider: IMonitoringProvider): Promise<void> {
    // Check compliance before registration
    const complianceReport = await MonitoringInterfaceComplianceChecker.checkCompliance(provider);

    if (!complianceReport.overallCompliance) {
      throw new Error(
        `Provider ${provider.name} v${provider.version} does not meet compliance requirements: ` +
        complianceReport.errors.join(', ')
      );
    }

    const registeredProvider: RegisteredProvider = {
      provider,
      registeredAt: new Date().toISOString(),
      complianceReport,
      lastHealthCheck: new Date().toISOString(),
      isHealthy: true,
    };

    this.providers.set(provider.name, registeredProvider);
    this.complianceCache.set(provider.name, complianceReport);
  }

  /**
   * Get a registered provider
   */
  getProvider(name: string): IMonitoringProvider | undefined {
    const registered = this.providers.get(name);
    return registered?.provider;
  }

  /**
   * List all registered providers
   */
  listProviders(): string[] {
    return Array.from(this.providers.keys());
  }

  /**
   * Get compliance report for a provider
   */
  async getComplianceReport(name: string): Promise<ComplianceReport | null> {
    const cached = this.complianceCache.get(name);
    const now = Date.now();

    // Return cached report if still valid
    if (cached && (now - new Date(cached.providerVersion).getTime()) < this.cacheTimeoutMs) {
      return cached;
    }

    const provider = this.getProvider(name);
    if (!provider) {
      return null;
    }

    // Generate fresh compliance report
    const report = await MonitoringInterfaceComplianceChecker.checkCompliance(provider);
    this.complianceCache.set(name, report);
    return report;
  }

  /**
   * Check health of all providers
   */
  async checkAllProvidersHealth(): Promise<Record<string, boolean>> {
    const health: Record<string, boolean> = {};

    for (const [name, registered] of this.providers) {
      try {
        registered.isHealthy = await registered.provider.isHealthy();
        registered.lastHealthCheck = new Date().toISOString();
        health[name] = registered.isHealthy;
      } catch (error) {
        registered.isHealthy = false;
        registered.lastHealthCheck = new Date().toISOString();
        health[name] = false;
      }
    }

    return health;
  }

  /**
   * Unregister a provider
   */
  unregisterProvider(name: string): boolean {
    const removed = this.providers.delete(name);
    this.complianceCache.delete(name);
    return removed;
  }

  /**
   * Get provider statistics
   */
  getStatistics(): {
    totalProviders: number;
    healthyProviders: number;
    compliantProviders: number;
    providers: Array<{
      name: string;
      version: string;
      healthy: boolean;
      compliant: boolean;
      lastHealthCheck: string;
    }>;
  } {
    const providers = Array.from(this.providers.entries()).map(([name, registered]) => ({
      name,
      version: registered.provider.version,
      healthy: registered.isHealthy,
      compliant: registered.complianceReport.overallCompliance,
      lastHealthCheck: registered.lastHealthCheck,
    }));

    const healthyCount = providers.filter(p => p.healthy).length;
    const compliantCount = providers.filter(p => p.compliant).length;

    return {
      totalProviders: providers.length,
      healthyProviders: healthyCount,
      compliantProviders: compliantCount,
      providers,
    };
  }
}

/**
 * Registered provider information
 */
interface RegisteredProvider {
  provider: IMonitoringProvider;
  registeredAt: string;
  complianceReport: ComplianceReport;
  lastHealthCheck: string;
  isHealthy: boolean;
}

// ============================================================================
// Global Registry Instance
// ============================================================================

/**
 * Global monitoring provider registry instance
 */
export const monitoringProviderRegistry = new MonitoringProviderRegistry();