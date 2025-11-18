/**
 * SLO Metrics Validator
 *
 * Validates and standardizes metrics emission for SLO compliance.
 * Ensures stable metric names and consistent labels across the system.
 *
 * @version 1.0.0
 * @since 2025-11-14
 */

import { EventEmitter } from 'events';

import type { TypedMetric } from '../types/metrics-types.js';

// ============================================================================
// Stable Metric Names (as defined in SLO documentation)
// ============================================================================

export const CORTEX_METRIC_NAMES = {
  // Core SLO metrics
  AVAILABILITY_SUCCESS_RATE: 'cortex_availability_success_rate',
  REQUEST_DURATION: 'cortex_request_duration_seconds',
  ERROR_RATE: 'cortex_error_rate',

  // Qdrant metrics
  QDRANT_OPERATION_DURATION: 'cortex_qdrant_operation_duration_seconds',
  QDRANT_OPERATION_SUCCESS_RATE: 'cortex_qdrant_operation_success_rate',

  // Memory store metrics
  MEMORY_STORE_QPS: 'cortex_memory_store_qps',
  MEMORY_FIND_QPS: 'cortex_memory_find_qps',
  TOTAL_QPS: 'cortex_total_qps',

  // Quality metrics
  CACHE_HIT_RATE: 'cortex_cache_hit_rate',
  DEDUPLICATION_RATE: 'cortex_deduplication_rate',
  EMBEDDING_SUCCESS_RATE: 'cortex_embedding_success_rate',

  // System metrics
  MEMORY_USAGE: 'cortex_memory_usage_bytes',
  CPU_USAGE: 'cortex_cpu_usage_percent',
  ACTIVE_CONNECTIONS: 'cortex_active_connections',

  // Business metrics
  MCP_TOOL_EXECUTIONS: 'cortex_mcp_tool_executions_total',
  MCP_TOOL_SUCCESS_RATE: 'cortex_mcp_tool_success_rate',
  MCP_TOOL_DURATION: 'cortex_mcp_tool_duration_seconds',
} as const;

// ============================================================================
// Standard Label Sets
// ============================================================================

export const STANDARD_LABELS = {
  SERVICE: 'service',
  VERSION: 'version',
  ENVIRONMENT: 'environment',
  COMPONENT: 'component',
  OPERATION_TYPE: 'operation_type',
  STATUS: 'status',
  ENDPOINT: 'endpoint',
  METHOD: 'method',
  ERROR_TYPE: 'error_type',
  COLLECTION: 'collection',
} as const;

export const STANDARD_VALUES = {
  SERVICE: 'cortex-mcp',
  COMPONENTS: {
    API: 'api',
    QDRANT: 'qdrant',
    MEMORY_STORE: 'memory-store',
    AI_ORCHESTRATOR: 'ai-orchestrator',
    DEDUPLICATION: 'deduplication',
  },
  ENVIRONMENTS: {
    PRODUCTION: 'production',
    STAGING: 'staging',
    DEVELOPMENT: 'development',
  },
  STATUSES: {
    SUCCESS: 'success',
    ERROR: 'error',
    TIMEOUT: 'timeout',
  },
} as const;

// ============================================================================
// Validation Interfaces
// ============================================================================

export interface MetricValidationRule {
  name: string;
  description: string;
  validator: (metric: TypedMetric) => ValidationResult;
  severity: 'error' | 'warning' | 'info';
  category: 'naming' | 'labeling' | 'value' | 'structure';
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  info: string[];
  suggestions?: string[];
}

export interface MetricsValidationReport {
  timestamp: string;
  totalMetrics: number;
  validMetrics: number;
  invalidMetrics: number;
  summary: {
    naming: { errors: number; warnings: number };
    labeling: { errors: number; warnings: number };
    value: { errors: number; warnings: number };
    structure: { errors: number; warnings: number };
  };
  issues: Array<{
    metricId: string;
    rule: string;
    severity: string;
    message: string;
    suggestion?: string;
  }>;
  recommendations: string[];
}

// ============================================================================
// SLO Metrics Validator Class
// ============================================================================

export class SLOMetricsValidator extends EventEmitter {
  private validationRules: MetricValidationRule[] = [];
  private knownMetrics: Set<string> = new Set();
  private validationHistory: MetricsValidationReport[] = [];

  constructor() {
    super();
    this.initializeValidationRules();
  }

  /**
   * Validate a single metric against all rules
   */
  validateMetric(metric: TypedMetric): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];
    const info: string[] = [];
    const suggestions: string[] = [];

    for (const rule of this.validationRules) {
      const result = rule.validator(metric);
      errors.push(...result.errors);
      warnings.push(...result.warnings);
      info.push(...result.info);
      if (result.suggestions) {
        suggestions.push(...result.suggestions);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      info,
      suggestions,
    };
  }

  /**
   * Validate multiple metrics and generate a comprehensive report
   */
  validateMetrics(metrics: TypedMetric[]): MetricsValidationReport {
    const now = new Date().toISOString();
    const totalMetrics = metrics.length;
    let validMetrics = 0;
    let invalidMetrics = 0;

    const summary = {
      naming: { errors: 0, warnings: 0 },
      labeling: { errors: 0, warnings: 0 },
      value: { errors: 0, warnings: 0 },
      structure: { errors: 0, warnings: 0 },
    };

    const issues: Array<{
      metricId: string;
      rule: string;
      severity: string;
      message: string;
      suggestion?: string;
    }> = [];

    for (const metric of metrics) {
      const validation = this.validateMetric(metric);

      if (validation.valid) {
        validMetrics++;
      } else {
        invalidMetrics++;
      }

      // Track issues by category
      for (const rule of this.validationRules) {
        const ruleResult = rule.validator(metric);
        if (ruleResult.errors.length > 0) {
          summary[rule.category].errors += ruleResult.errors.length;
          for (const error of ruleResult.errors) {
            issues.push({
              metricId: metric.id,
              rule: rule.name,
              severity: 'error',
              message: error,
              suggestion: ruleResult.suggestions?.[0],
            });
          }
        }
        if (ruleResult.warnings.length > 0) {
          summary[rule.category].warnings += ruleResult.warnings.length;
          for (const warning of ruleResult.warnings) {
            issues.push({
              metricId: metric.id,
              rule: rule.name,
              severity: 'warning',
              message: warning,
              suggestion: ruleResult.suggestions?.[0],
            });
          }
        }
      }
    }

    const report: MetricsValidationReport = {
      timestamp: now,
      totalMetrics,
      validMetrics,
      invalidMetrics,
      summary,
      issues,
      recommendations: this.generateRecommendations(summary, issues),
    };

    // Store in history
    this.validationHistory.push(report);
    if (this.validationHistory.length > 100) {
      this.validationHistory.shift(); // Keep last 100 reports
    }

    // Emit events
    this.emit('validation_completed', report);
    if (invalidMetrics > 0) {
      this.emit('validation_errors_found', {
        count: invalidMetrics,
        issues: issues.filter((i) => i.severity === 'error'),
      });
    }

    return report;
  }

  /**
   * Standardize a metric to ensure compliance with SLO requirements
   */
  standardizeMetric(metric: TypedMetric): TypedMetric {
    const standardized = { ...metric };

    // Standardize metric name
    standardized.name = this.standardizeMetricName(metric.name);

    // Ensure standard labels are present
    standardized.labels = {
      [STANDARD_LABELS.SERVICE]: STANDARD_VALUES.SERVICE,
      ...metric.labels,
    };

    // Validate and standardize label values
    for (const [key, value] of Object.entries(standardized.labels)) {
      standardized.labels[key] = this.standardizeLabelValue(key, value);
    }

    // Ensure dimensions are properly formatted
    standardized.dimensions = metric.dimensions.map((dim) => ({
      ...dim,
      name: dim.name.toLowerCase().replace(/[^a-z0-9_]/g, '_'),
      value: String(dim.value)
        .toLowerCase()
        .replace(/[^a-z0-9_]/g, '_'),
    }));

    // Set default quality if not provided
    if (!standardized.quality) {
      standardized.quality = {
        accuracy: 1.0,
        completeness: 1.0,
        consistency: 1.0,
        timeliness: 1.0,
        validity: 1.0,
        reliability: 1.0,
        lastValidated: new Date().toISOString(),
      };
    }

    return standardized;
  }

  /**
   * Get validation history
   */
  getValidationHistory(limit?: number): MetricsValidationReport[] {
    if (limit) {
      return this.validationHistory.slice(-limit);
    }
    return [...this.validationHistory];
  }

  /**
   * Get metrics compliance score
   */
  getComplianceScore(): number {
    if (this.validationHistory.length === 0) {
      return 100;
    }

    const latestReport = this.validationHistory[this.validationHistory.length - 1];
    if (latestReport.totalMetrics === 0) {
      return 100;
    }

    return Math.round((latestReport.validMetrics / latestReport.totalMetrics) * 100);
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  private initializeValidationRules(): void {
    this.validationRules = [
      // Naming rules
      {
        name: 'stable_metric_name',
        description: 'Metric name should use stable naming convention',
        validator: this.validateStableMetricName.bind(this),
        severity: 'error',
        category: 'naming',
      },
      {
        name: 'metric_name_format',
        description: 'Metric name should follow cortex_* naming pattern',
        validator: this.validateMetricNameFormat.bind(this),
        severity: 'warning',
        category: 'naming',
      },

      // Labeling rules
      {
        name: 'required_labels',
        description: 'Standard labels should be present',
        validator: this.validateRequiredLabels.bind(this),
        severity: 'warning',
        category: 'labeling',
      },
      {
        name: 'label_value_format',
        description: 'Label values should be properly formatted',
        validator: this.validateLabelValues.bind(this),
        severity: 'warning',
        category: 'labeling',
      },

      // Value rules
      {
        name: 'metric_value_type',
        description: 'Metric value should match metric type',
        validator: this.validateMetricValueType.bind(this),
        severity: 'error',
        category: 'value',
      },
      {
        name: 'timestamp_format',
        description: 'Timestamp should be in ISO format',
        validator: this.validateTimestampFormat.bind(this),
        severity: 'error',
        category: 'value',
      },

      // Structure rules
      {
        name: 'required_fields',
        description: 'Required metric fields should be present',
        validator: this.validateRequiredFields.bind(this),
        severity: 'error',
        category: 'structure',
      },
      {
        name: 'quality_indicators',
        description: 'Quality indicators should be within valid range',
        validator: this.validateQualityIndicators.bind(this),
        severity: 'warning',
        category: 'structure',
      },
    ];
  }

  private validateStableMetricName(metric: TypedMetric): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];
    const suggestions: string[] = [];

    const stableNames = Object.values(CORTEX_METRIC_NAMES);
    const isStableName = stableNames.includes(metric.name as typeof CORTEX_METRIC_NAMES[keyof typeof CORTEX_METRIC_NAMES]);

    if (!isStableName) {
      // Check if it follows the pattern but isn't in our known list
      if (metric.name.startsWith('cortex_')) {
        warnings.push(
          `Metric name '${metric.name}' follows cortex pattern but is not in stable names list`
        );
        suggestions.push(
          `Consider adding '${metric.name}' to CORTEX_METRIC_NAMES if it's a new metric`
        );
      } else {
        errors.push(`Metric name '${metric.name}' does not use stable naming convention`);
        suggestions.push(`Use stable names like '${stableNames[0]}' or follow 'cortex_*' pattern`);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      info: isStableName ? [`Using stable metric name: ${metric.name}`] : [],
      suggestions,
    };
  }

  private validateMetricNameFormat(metric: TypedMetric): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!metric.name.match(/^[a-z][a-z0-9_]*$/)) {
      errors.push('Metric name should contain only lowercase letters, numbers, and underscores');
      errors.push('Metric name should start with a letter');
    }

    if (metric.name.length > 100) {
      warnings.push('Metric name is very long, consider abbreviating');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      info: [],
    };
  }

  private validateRequiredLabels(metric: TypedMetric): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    const requiredLabels = [
      STANDARD_LABELS.SERVICE,
      STANDARD_LABELS.COMPONENT,
      STANDARD_LABELS.ENVIRONMENT,
    ];

    for (const label of requiredLabels) {
      if (!metric.labels[label]) {
        warnings.push(`Missing recommended label: ${label}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      info: [],
    };
  }

  private validateLabelValues(metric: TypedMetric): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    for (const [key, value] of Object.entries(metric.labels)) {
      if (typeof value !== 'string') {
        errors.push(`Label '${key}' value should be a string, got ${typeof value}`);
      } else if (value.length > 200) {
        warnings.push(`Label '${key}' value is very long (${value.length} chars)`);
      } else if (!value.match(/^[a-zA-Z0-9_-]*$/)) {
        warnings.push(`Label '${key}' value contains special characters that may cause issues`);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      info: [],
    };
  }

  private validateMetricValueType(metric: TypedMetric): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (typeof metric.value !== 'number' && typeof metric.value !== 'string') {
      errors.push('Metric value should be a number or string');
    }

    // Type-specific validations
    if (metric.type === 'counter' && typeof metric.value !== 'number') {
      errors.push('Counter metrics should have numeric values');
    }

    if (metric.type === 'gauge' && typeof metric.value !== 'number') {
      errors.push('Gauge metrics should have numeric values');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      info: [],
    };
  }

  private validateTimestampFormat(metric: TypedMetric): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!metric.timestamp) {
      errors.push('Timestamp is required');
      return { valid: false, errors, warnings, info: [] };
    }

    const timestamp = new Date(metric.timestamp);
    if (isNaN(timestamp.getTime())) {
      errors.push('Timestamp should be in valid ISO format');
    }

    // Check if timestamp is too old or too far in future
    const now = new Date();
    const diffHours = Math.abs(timestamp.getTime() - now.getTime()) / (1000 * 60 * 60);

    if (diffHours > 24) {
      warnings.push('Timestamp is more than 24 hours away from current time');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      info: [],
    };
  }

  private validateRequiredFields(metric: TypedMetric): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    const requiredFields = ['id', 'name', 'type', 'timestamp', 'component'];
    for (const field of requiredFields) {
      if (!metric[field as keyof TypedMetric]) {
        errors.push(`Required field '${field}' is missing`);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      info: [],
    };
  }

  private validateQualityIndicators(metric: TypedMetric): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!metric.quality) {
      warnings.push('Quality indicators are missing');
      return { valid: true, errors, warnings, info: [] };
    }

    const qualityFields = [
      'accuracy',
      'completeness',
      'consistency',
      'timeliness',
      'validity',
      'reliability',
    ];
    for (const field of qualityFields) {
      const value = metric.quality[field as keyof typeof metric.quality] as number;
      if (typeof value !== 'number' || value < 0 || value > 1) {
        warnings.push(`Quality indicator '${field}' should be a number between 0 and 1`);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      info: [],
    };
  }

  private standardizeMetricName(name: string): string {
    // Convert to standard cortex naming
    if (!name.startsWith('cortex_')) {
      // Convert common patterns to cortex naming
      const conversions: Record<string, string> = {
        qps: 'cortex_total_qps',
        latency: 'cortex_request_duration_seconds',
        error_rate: 'cortex_error_rate',
        memory_usage: 'cortex_memory_usage_bytes',
      };

      return (
        conversions[name.toLowerCase()] || `cortex_${name.toLowerCase().replace(/[^a-z0-9]/g, '_')}`
      );
    }

    return name.toLowerCase().replace(/[^a-z0-9_]/g, '_');
  }

  private standardizeLabelValue(key: string, value: string): string {
    // Standardize common label values
    if (key === STANDARD_LABELS.SERVICE) {
      return STANDARD_VALUES.SERVICE;
    }

    if (key === STANDARD_LABELS.COMPONENT) {
      const componentValue = value.toLowerCase().replace(/[^a-z0-9]/g, '-');
      // Check if it matches known components
      for (const [name, standardValue] of Object.entries(STANDARD_VALUES.COMPONENTS)) {
        if (
          componentValue.includes(name.toLowerCase()) ||
          name.toLowerCase().includes(componentValue)
        ) {
          return standardValue;
        }
      }
      return componentValue;
    }

    return String(value)
      .toLowerCase()
      .replace(/[^a-z0-9_-]/g, '_');
  }

  private generateRecommendations(
    summary: MetricsValidationReport['summary'],
    issues: MetricsValidationReport['issues']
  ): string[] {
    const recommendations: string[] = [];

    if (summary.naming.errors > 0) {
      recommendations.push(
        'Review metric naming conventions and update to use stable names from CORTEX_METRIC_NAMES'
      );
    }

    if (summary.labeling.errors > 0) {
      recommendations.push(
        'Ensure all metrics include required standard labels (service, component, environment)'
      );
    }

    if (summary.value.errors > 0) {
      recommendations.push('Validate metric value types match the declared metric type');
    }

    if (summary.structure.errors > 0) {
      recommendations.push('Review metric structure to ensure all required fields are present');
    }

    if (issues.length > 10) {
      recommendations.push('Consider implementing automated metric validation in the pipeline');
    }

    // Specific recommendations based on common issues
    const commonIssues = issues.reduce(
      (acc, issue) => {
        acc[issue.rule] = (acc[issue.rule] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );

    if (commonIssues['required_labels'] > 0) {
      recommendations.push(
        'Add standardization middleware to automatically inject required labels'
      );
    }

    if (commonIssues['stable_metric_name'] > 0) {
      recommendations.push(
        'Update metric definitions to use stable names from the SLO specification'
      );
    }

    return recommendations;
  }
}

// Export singleton instance
export const sloMetricsValidator = new SLOMetricsValidator();
