/**
 * Retry Budget Monitoring System - Main Export
 *
 * Comprehensive retry budget and circuit breaker monitoring system with real-time
 * metrics, alerting, dashboards, and integration capabilities.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

// Core monitoring components
export {
  comprehensiveRetryDashboard,
  type ServiceDependency,
  type ServiceHealthMetrics,
} from './comprehensive-retry-dashboard.js';
export { enhancedCircuitDashboard } from './enhanced-circuit-dashboard.js';
export {
  type Alert,
  type AlertRule,
  type AlertSeverity,
  type AlertType,
  type EscalationPolicy,
  retryAlertSystem,
} from './retry-alert-system.js';
export {
  type RetryBudgetConfig,
  type RetryBudgetMetrics,
  retryBudgetMonitor,
  type RetryConsumptionEvent,
} from './retry-budget-monitor.js';
export {
  type ExportFormat,
  type MetricsExporterConfig,
  retryMetricsExporter,
} from './retry-metrics-exporter.js';
export {
  retryMonitoringIntegration,
  type RetryMonitoringIntegrationConfig,
  type ServiceRegistration,
  type UnifiedMonitoringStatus,
} from './retry-monitoring-integration.js';
export {
  type AnomalyDetection,
  type PatternDetection,
  type PredictiveAnalysis,
  retryTrendAnalyzer,
  type TrendAnalysis,
} from './retry-trend-analyzer.js';

import { retryMonitoringIntegration } from './retry-monitoring-integration.js';
import { type RetryBudgetConfig } from './retry-budget-monitor.js';

/**
 * Service registration options for retry budget monitoring
 */
export interface ServiceRegistrationOptions {
  maxRetriesPerMinute?: number;
  maxRetriesPerHour?: number;
  maxRetryRatePercent?: number;
  resetIntervalMinutes?: number;
  warningThresholdPercent?: number;
  criticalThresholdPercent?: number;
  sloTargetSuccessRate?: number;
  sloTargetResponseTime?: number;
  adaptiveBudgeting?: boolean;
  minBudgetRetries?: number;
  maxBudgetRetries?: number;
  dependencies?: string[];
  sloTargets?: {
    availability?: number;
    latency?: number;
    errorRate?: number;
  };
  team?: string;
  environment?: string;
}

/**
 * Type guard to validate service registration options
 */
export function isServiceRegistrationOptions(obj: unknown): obj is ServiceRegistrationOptions {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const opts = obj as Record<string, unknown>;

  // Validate numeric properties if they exist
  const numericProps = [
    'maxRetriesPerMinute',
    'maxRetriesPerHour',
    'maxRetryRatePercent',
    'resetIntervalMinutes',
    'warningThresholdPercent',
    'criticalThresholdPercent',
    'sloTargetSuccessRate',
    'sloTargetResponseTime',
    'minBudgetRetries',
    'maxBudgetRetries'
  ];

  for (const prop of numericProps) {
    if (opts[prop] !== undefined && typeof opts[prop] !== 'number') {
      return false;
    }
  }

  // Validate boolean properties if they exist
  if (opts.adaptiveBudgeting !== undefined && typeof opts.adaptiveBudgeting !== 'boolean') {
    return false;
  }

  // Validate array properties if they exist
  if (opts.dependencies !== undefined && !Array.isArray(opts.dependencies)) {
    return false;
  }

  // Validate object properties if they exist
  if (opts.sloTargets !== undefined && typeof opts.sloTargets !== 'object') {
    return false;
  }

  return true;
}

/**
 * Configuration for retry budget monitoring setup
 */
export interface RetryBudgetMonitoringConfig {
  services?: ServiceRegistrationOptions[];
  globalSettings?: {
    collectionIntervalMs?: number;
    predictionIntervalMinutes?: number;
    historyRetentionHours?: number;
    alertingEnabled?: boolean;
    exportEnabled?: boolean;
  };
}

/**
 * Type guard to validate retry budget monitoring configuration
 */
export function isRetryBudgetMonitoringConfig(obj: unknown): obj is RetryBudgetMonitoringConfig {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const config = obj as Record<string, unknown>;

  // Validate services array if it exists
  if (config.services !== undefined && !Array.isArray(config.services)) {
    return false;
  }

  // Validate globalSettings if it exists
  if (config.globalSettings !== undefined && typeof config.globalSettings !== 'object') {
    return false;
  }

  return true;
}

/**
 * Safely extract a numeric property from an unknown object
 */
function safeExtractNumber(obj: unknown, key: string, defaultValue: number): number {
  if (obj && typeof obj === 'object') {
    const record = obj as Record<string, unknown>;
    return typeof record[key] === 'number' ? record[key] : defaultValue;
  }
  return defaultValue;
}

/**
 * Safely extract a boolean property from an unknown object
 */
function safeExtractBoolean(obj: unknown, key: string, defaultValue: boolean): boolean {
  if (obj && typeof obj === 'object') {
    const record = obj as Record<string, unknown>;
    return typeof record[key] === 'boolean' ? record[key] : defaultValue;
  }
  return defaultValue;
}

/**
 * Safely extract an array property from an unknown object
 */
function safeExtractArray<T>(obj: unknown, key: string, defaultValue: T[]): T[] {
  if (obj && typeof obj === 'object') {
    const record = obj as Record<string, unknown>;
    return Array.isArray(record[key]) ? record[key] as T[] : defaultValue;
  }
  return defaultValue;
}

/**
 * Safely extract an object property from an unknown object
 */
function safeExtractObject(obj: unknown, key: string, defaultValue: Record<string, unknown>): Record<string, unknown> {
  if (obj && typeof obj === 'object') {
    const record = obj as Record<string, unknown>;
    return typeof record[key] === 'object' && record[key] !== null ? record[key] as Record<string, unknown> : defaultValue;
  }
  return defaultValue;
}

// Convenience functions for quick setup
export async function setupRetryBudgetMonitoring(config?: unknown) {
  const integration = retryMonitoringIntegration;

  if (config && isRetryBudgetMonitoringConfig(config)) {
    // Apply global settings if provided
    if (config.globalSettings) {
      // Configuration would be applied here
      // For now, we'll just log that settings were provided
      console.log('Retry budget monitoring configuration provided:', config.globalSettings);
    }

    // Register services if provided
    if (config.services) {
      for (const serviceConfig of config.services) {
        if (serviceConfig && isServiceRegistrationOptions(serviceConfig)) {
          // Extract service name from config or use a default
          const serviceName = serviceConfig.team || 'unknown-service';
          const circuitBreakerName = `${serviceName}-circuit-breaker`;

          await registerServiceForMonitoring(serviceName, circuitBreakerName, serviceConfig);
        }
      }
    }
  }

  await integration.initialize();
  await integration.start();

  return integration;
}

export async function registerServiceForMonitoring(
  serviceName: string,
  circuitBreakerName: string,
  options?: unknown
) {
  // Validate options using type guard
  const validOptions = options && isServiceRegistrationOptions(options) ? options : undefined;

  // Extract sloTargets safely
  const sloTargetsObj = safeExtractObject(validOptions, 'sloTargets', {});
  const sloTargets = {
    availability: safeExtractNumber(sloTargetsObj, 'availability', 99.9),
    latency: safeExtractNumber(sloTargetsObj, 'latency', 500),
    errorRate: safeExtractNumber(sloTargetsObj, 'errorRate', 0.1),
  };

  // Create registration with safe property access
  const registration = {
    serviceName,
    circuitBreakerName,
    retryBudgetConfig: {
      serviceName,
      circuitBreakerName,
      maxRetriesPerMinute: safeExtractNumber(validOptions, 'maxRetriesPerMinute', 60),
      maxRetriesPerHour: safeExtractNumber(validOptions, 'maxRetriesPerHour', 1000),
      maxRetryRatePercent: safeExtractNumber(validOptions, 'maxRetryRatePercent', 10),
      resetIntervalMinutes: safeExtractNumber(validOptions, 'resetIntervalMinutes', 60),
      warningThresholdPercent: safeExtractNumber(validOptions, 'warningThresholdPercent', 75),
      criticalThresholdPercent: safeExtractNumber(validOptions, 'criticalThresholdPercent', 90),
      sloTargetSuccessRate: safeExtractNumber(validOptions, 'sloTargetSuccessRate', 99.9),
      sloTargetResponseTime: safeExtractNumber(validOptions, 'sloTargetResponseTime', 500),
      adaptiveBudgeting: safeExtractBoolean(validOptions, 'adaptiveBudgeting', true),
      minBudgetRetries: safeExtractNumber(validOptions, 'minBudgetRetries', 10),
      maxBudgetRetries: safeExtractNumber(validOptions, 'maxBudgetRetries', 500),
    } as RetryBudgetConfig,
    dependencies: safeExtractArray(validOptions, 'dependencies', []),
    sloTargets,
    team: validOptions?.team,
    environment: validOptions?.environment,
  };

  retryMonitoringIntegration.registerService(registration);

  return registration;
}

// Health check utility
export async function getRetryBudgetHealthReport() {
  return await retryMonitoringIntegration.getHealthReport();
}

// Metrics export utility
export async function exportRetryBudgetMetrics(format: 'prometheus' | 'json' | 'csv' = 'json') {
  return await retryMonitoringIntegration.exportUnifiedMetrics(format);
}

// Quick status utility
export function getRetryBudgetMonitoringStatus() {
  return retryMonitoringIntegration.getMonitoringStatus();
}
