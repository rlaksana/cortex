
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
export { comprehensiveRetryDashboard, type ServiceDependency, type ServiceHealthMetrics } from './comprehensive-retry-dashboard.js';
export { enhancedCircuitDashboard } from './enhanced-circuit-dashboard.js';
export { type Alert, type AlertRule, type AlertSeverity, type AlertType, type EscalationPolicy,retryAlertSystem } from './retry-alert-system.js';
export { type RetryBudgetConfig, type RetryBudgetMetrics, retryBudgetMonitor, type RetryConsumptionEvent } from './retry-budget-monitor.js';
export { type ExportFormat, type MetricsExporterConfig,retryMetricsExporter } from './retry-metrics-exporter.js';
export { retryMonitoringIntegration, type RetryMonitoringIntegrationConfig,type ServiceRegistration, type UnifiedMonitoringStatus } from './retry-monitoring-integration.js';
export { type AnomalyDetection, type PatternDetection,type PredictiveAnalysis, retryTrendAnalyzer, type TrendAnalysis } from './retry-trend-analyzer.js';

import { retryMonitoringIntegration } from './retry-monitoring-integration.js';

// Convenience functions for quick setup
export async function setupRetryBudgetMonitoring(config?: any) {
  const integration = retryMonitoringIntegration;

  if (config) {
    // Configuration would be applied here
  }

  await integration.initialize();
  await integration.start();

  return integration;
}

export async function registerServiceForMonitoring(serviceName: string, circuitBreakerName: string, options?: any) {
  const registration = {
    serviceName,
    circuitBreakerName,
    retryBudgetConfig: {
      serviceName,
      circuitBreakerName,
      maxRetriesPerMinute: options?.maxRetriesPerMinute || 60,
      maxRetriesPerHour: options?.maxRetriesPerHour || 1000,
      maxRetryRatePercent: options?.maxRetryRatePercent || 10,
      resetIntervalMinutes: options?.resetIntervalMinutes || 60,
      warningThresholdPercent: options?.warningThresholdPercent || 75,
      criticalThresholdPercent: options?.criticalThresholdPercent || 90,
      sloTargetSuccessRate: options?.sloTargetSuccessRate || 99.9,
      sloTargetResponseTime: options?.sloTargetResponseTime || 500,
      adaptiveBudgeting: options?.adaptiveBudgeting ?? true,
      minBudgetRetries: options?.minBudgetRetries || 10,
      maxBudgetRetries: options?.maxBudgetRetries || 500,
    },
    dependencies: options?.dependencies || [],
    sloTargets: options?.sloTargets || {
      availability: 99.9,
      latency: 500,
      errorRate: 0.1,
    },
    team: options?.team,
    environment: options?.environment,
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