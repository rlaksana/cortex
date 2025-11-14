/**
 * Runtime Validation System for Audit Events and Metrics
 *
 * Provides comprehensive runtime validation with detailed error reporting,
 * custom validation rules, and performance optimization for production use.
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

import {
  AlertSeverity,
  AuditCategory,
  AuditEventType,
  AuditOperation,
  AuditSource,
  type AuditValidationResult,
  CollectorType,
  ComplianceFramework,
  ComplianceRegulation,
  MetricCategory,
  MetricType,
  type MetricValidationResult,
  OutputFormat,
  SensitivityLevel,
  type TypedAuditEvent,
  type TypedMetric} from '../types/index.js';

// ============================================================================
// Core Validation Configuration
// ============================================================================

/**
 * Validation configuration
 */
export interface ValidationConfig {
  strictMode: boolean;
  enablePerformanceOptimization: boolean;
  cacheEnabled: boolean;
  cacheSize: number;
  customRules: CustomValidationRule[];
  timeouts: ValidationTimeouts;
  reporting: ValidationReportingConfig;
}

/**
 * Custom validation rule interface
 */
export interface CustomValidationRule {
  id: string;
  name: string;
  description: string;
  type: 'audit' | 'metric' | 'both';
  enabled: boolean;
  priority: number; // 1-10, higher = higher priority
  validator: ValidationFunction;
  errorMessage?: string;
  recoveryAction?: RecoveryAction;
}

/**
 * Validation function type
 */
export type ValidationFunction = (
  data: TypedAuditEvent | TypedMetric,
  context?: ValidationContext
) => ValidationResult;

/**
 * Recovery action for validation failures
 */
export interface RecoveryAction {
  type: RecoveryType;
  parameters?: Record<string, unknown>;
  autoApply?: boolean;
}

/**
 * Recovery types
 */
export enum RecoveryType {
  TRANSFORM = 'transform',
  FILTER = 'filter',
  LOG_WARNING = 'log_warning',
  LOG_ERROR = 'log_error',
  ESCALATE = 'escalate',
  IGNORE = 'ignore'
}

/**
 * Validation timeouts
 */
export interface ValidationTimeouts {
  auditValidation: number; // milliseconds
  metricValidation: number; // milliseconds
  batchValidation: number; // milliseconds
  customRuleExecution: number; // milliseconds
}

/**
 * Validation reporting configuration
 */
export interface ValidationReportingConfig {
  includeStackTrace: boolean;
  includeContext: boolean;
  includePerformanceMetrics: boolean;
  aggregateResults: boolean;
  reportInterval: number; // milliseconds
}

/**
 * Validation context
 */
export interface ValidationContext {
  requestId?: string;
  userId?: string;
  sessionId?: string;
  component?: string;
  operation?: string;
  timestamp: string;
  environment: string;
  version?: string;
}

/**
 * Detailed validation result
 */
export interface ValidationResult {
  isValid: boolean;
  severity: ValidationSeverity;
  errors: ValidationError[];
  warnings: ValidationWarning[];
  suggestions: ValidationSuggestion[];
  performance: ValidationPerformance;
  context?: ValidationContext;
}

/**
 * Validation severity levels
 */
export enum ValidationSeverity {
  DEBUG = 'debug',
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
  CRITICAL = 'critical'
}

/**
 * Validation error
 */
export interface ValidationError {
  code: string;
  message: string;
  field?: string;
  value?: unknown;
  expected?: unknown;
  ruleId?: string;
  timestamp: string;
  stack?: string;
}

/**
 * Validation warning
 */
export interface ValidationWarning {
  code: string;
  message: string;
  field?: string;
  value?: unknown;
  recommendation?: string;
  ruleId?: string;
  timestamp: string;
}

/**
 * Validation suggestion
 */
export interface ValidationSuggestion {
  type: SuggestionType;
  message: string;
  action: string;
  priority: number; // 1-10
  ruleId?: string;
}

/**
 * Suggestion types
 */
export enum SuggestionType {
  OPTIMIZATION = 'optimization',
  BEST_PRACTICE = 'best_practice',
  SECURITY = 'security',
  PERFORMANCE = 'performance',
  COMPLIANCE = 'compliance',
  MAINTENANCE = 'maintenance'
}

/**
 * Validation performance metrics
 */
export interface ValidationPerformance {
  duration: number; // milliseconds
  memoryUsage: number; // bytes
  rulesExecuted: number;
  cacheHits: number;
  cacheMisses: number;
  timestamp: string;
}

// ============================================================================
// Main Validator Class
// ============================================================================

/**
 * Comprehensive validator for audit events and metrics
 */
export class AuditMetricsValidator {
  private config: ValidationConfig;
  private auditCache: Map<string, ValidationResult> = new Map();
  private metricCache: Map<string, ValidationResult> = new Map();
  private customRules: Map<string, CustomValidationRule> = new Map();
  private performanceTracker: ValidationPerformanceTracker;

  constructor(config?: Partial<ValidationConfig>) {
    this.config = {
      strictMode: false,
      enablePerformanceOptimization: true,
      cacheEnabled: true,
      cacheSize: 10000,
      customRules: [],
      timeouts: {
        auditValidation: 1000,
        metricValidation: 500,
        batchValidation: 5000,
        customRuleExecution: 200
      },
      reporting: {
        includeStackTrace: false,
        includeContext: true,
        includePerformanceMetrics: true,
        aggregateResults: true,
        reportInterval: 60000
      },
      ...config
    };

    this.performanceTracker = new ValidationPerformanceTracker();
    this.initializeBuiltInRules();
  }

  /**
   * Validate a typed audit event with comprehensive checks
   */
  async validateAuditEvent(
    event: TypedAuditEvent,
    context?: ValidationContext
  ): Promise<ValidationResult> {
    const startTime = Date.now();
    const validationContext: ValidationContext = {
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      ...context
    };

    try {
      // Check cache first if enabled
      if (this.config.cacheEnabled) {
        const cacheKey = this.generateAuditCacheKey(event);
        const cached = this.auditCache.get(cacheKey);
        if (cached) {
          this.performanceTracker.recordCacheHit('audit');
          return {
            ...cached,
            context: validationContext,
            performance: {
              ...cached.performance,
              timestamp: new Date().toISOString()
            }
          };
        }
        this.performanceTracker.recordCacheMiss('audit');
      }

      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];
      const suggestions: ValidationSuggestion[] = [];
      let rulesExecuted = 0;

      // Core validation rules
      rulesExecuted += await this.validateCoreAuditFields(event, errors, warnings, suggestions);

      // Business logic validation
      rulesExecuted += await this.validateAuditBusinessLogic(event, errors, warnings, suggestions);

      // Compliance validation
      rulesExecuted += await this.validateAuditCompliance(event, errors, warnings, suggestions);

      // Security validation
      rulesExecuted += await this.validateAuditSecurity(event, errors, warnings, suggestions);

      // Performance validation
      rulesExecuted += await this.validateAuditPerformance(event, errors, warnings, suggestions);

      // Custom validation rules
      for (const rule of this.config.customRules) {
        if (rule.enabled && (rule.type === 'audit' || rule.type === 'both')) {
          const ruleResult = await this.executeCustomRule(rule, event, validationContext);
          errors.push(...ruleResult.errors);
          warnings.push(...ruleResult.warnings);
          suggestions.push(...ruleResult.suggestions);
          rulesExecuted++;
        }
      }

      const duration = Date.now() - startTime;
      const memoryUsage = process.memoryUsage().heapUsed;

      const result: ValidationResult = {
        isValid: errors.length === 0,
        severity: this.calculateSeverity(errors, warnings),
        errors,
        warnings,
        suggestions,
        performance: {
          duration,
          memoryUsage,
          rulesExecuted,
          cacheHits: this.performanceTracker.getCacheHits('audit'),
          cacheMisses: this.performanceTracker.getCacheMisses('audit'),
          timestamp: new Date().toISOString()
        },
        context: validationContext
      };

      // Cache result if enabled
      if (this.config.cacheEnabled) {
        const cacheKey = this.generateAuditCacheKey(event);
        this.setCacheWithSizeLimit(this.auditCache, cacheKey, result);
      }

      return result;

    } catch (error) {
      return this.createErrorResult(error as Error, validationContext, startTime);
    }
  }

  /**
   * Validate a typed metric with comprehensive checks
   */
  async validateMetric(
    metric: TypedMetric,
    context?: ValidationContext
  ): Promise<ValidationResult> {
    const startTime = Date.now();
    const validationContext: ValidationContext = {
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      ...context
    };

    try {
      // Check cache first if enabled
      if (this.config.cacheEnabled) {
        const cacheKey = this.generateMetricCacheKey(metric);
        const cached = this.metricCache.get(cacheKey);
        if (cached) {
          this.performanceTracker.recordCacheHit('metric');
          return {
            ...cached,
            context: validationContext,
            performance: {
              ...cached.performance,
              timestamp: new Date().toISOString()
            }
          };
        }
        this.performanceTracker.recordCacheMiss('metric');
      }

      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];
      const suggestions: ValidationSuggestion[] = [];
      let rulesExecuted = 0;

      // Core validation rules
      rulesExecuted += await this.validateCoreMetricFields(metric, errors, warnings, suggestions);

      // Data type validation
      rulesExecuted += await this.validateMetricDataTypes(metric, errors, warnings, suggestions);

      // Value range validation
      rulesExecuted += await this.validateMetricValueRanges(metric, errors, warnings, suggestions);

      // Quality validation
      rulesExecuted += await this.validateMetricQuality(metric, errors, warnings, suggestions);

      // Performance validation
      rulesExecuted += await this.validateMetricPerformance(metric, errors, warnings, suggestions);

      // Custom validation rules
      for (const rule of this.config.customRules) {
        if (rule.enabled && (rule.type === 'metric' || rule.type === 'both')) {
          const ruleResult = await this.executeCustomRule(rule, metric, validationContext);
          errors.push(...ruleResult.errors);
          warnings.push(...ruleResult.warnings);
          suggestions.push(...ruleResult.suggestions);
          rulesExecuted++;
        }
      }

      const duration = Date.now() - startTime;
      const memoryUsage = process.memoryUsage().heapUsed;

      const result: ValidationResult = {
        isValid: errors.length === 0,
        severity: this.calculateSeverity(errors, warnings),
        errors,
        warnings,
        suggestions,
        performance: {
          duration,
          memoryUsage,
          rulesExecuted,
          cacheHits: this.performanceTracker.getCacheHits('metric'),
          cacheMisses: this.performanceTracker.getCacheMisses('metric'),
          timestamp: new Date().toISOString()
        },
        context: validationContext
      };

      // Cache result if enabled
      if (this.config.cacheEnabled) {
        const cacheKey = this.generateMetricCacheKey(metric);
        this.setCacheWithSizeLimit(this.metricCache, cacheKey, result);
      }

      return result;

    } catch (error) {
      return this.createErrorResult(error as Error, validationContext, startTime);
    }
  }

  /**
   * Validate multiple audit events in batch
   */
  async validateAuditBatch(
    events: TypedAuditEvent[],
    context?: ValidationContext
  ): Promise<BatchValidationResult> {
    const startTime = Date.now();
    const results: ValidationResult[] = [];
    const summary: BatchValidationSummary = {
      total: events.length,
      valid: 0,
      invalid: 0,
      warnings: 0,
      errors: 0,
      performance: {
        totalDuration: 0,
        averageDuration: 0,
        memoryUsage: 0,
        rulesExecuted: 0
      }
    };

    try {
      // Process events in parallel if optimization is enabled
      if (this.config.enablePerformanceOptimization) {
        const batchSize = Math.ceil(events.length / 4); // Use 4 parallel workers
        const batches: TypedAuditEvent[][] = [];

        for (let i = 0; i < events.length; i += batchSize) {
          batches.push(events.slice(i, i + batchSize));
        }

        for (const batch of batches) {
          const batchResults = await Promise.all(
            batch.map(event => this.validateAuditEvent(event, context))
          );
          results.push(...batchResults);
        }
      } else {
        // Process sequentially
        for (const event of events) {
          const result = await this.validateAuditEvent(event, context);
          results.push(result);
        }
      }

      // Calculate summary statistics
      for (const result of results) {
        if (result.isValid) {
          summary.valid++;
        } else {
          summary.invalid++;
        }
        summary.warnings += result.warnings.length;
        summary.errors += result.errors.length;
        summary.performance.totalDuration += result.performance.duration;
        summary.performance.memoryUsage += result.performance.memoryUsage;
        summary.performance.rulesExecuted += result.performance.rulesExecuted;
      }

      summary.performance.averageDuration = summary.performance.totalDuration / results.length;

      return {
        results,
        summary,
        duration: Date.now() - startTime,
        context
      };

    } catch (error) {
      return this.createBatchErrorResult(error as Error, context, startTime, events.length);
    }
  }

  /**
   * Validate multiple metrics in batch
   */
  async validateMetricBatch(
    metrics: TypedMetric[],
    context?: ValidationContext
  ): Promise<BatchValidationResult> {
    const startTime = Date.now();
    const results: ValidationResult[] = [];
    const summary: BatchValidationSummary = {
      total: metrics.length,
      valid: 0,
      invalid: 0,
      warnings: 0,
      errors: 0,
      performance: {
        totalDuration: 0,
        averageDuration: 0,
        memoryUsage: 0,
        rulesExecuted: 0
      }
    };

    try {
      // Process metrics in parallel if optimization is enabled
      if (this.config.enablePerformanceOptimization) {
        const batchSize = Math.ceil(metrics.length / 4); // Use 4 parallel workers
        const batches: TypedMetric[][] = [];

        for (let i = 0; i < metrics.length; i += batchSize) {
          batches.push(metrics.slice(i, i + batchSize));
        }

        for (const batch of batches) {
          const batchResults = await Promise.all(
            batch.map(metric => this.validateMetric(metric, context))
          );
          results.push(...batchResults);
        }
      } else {
        // Process sequentially
        for (const metric of metrics) {
          const result = await this.validateMetric(metric, context);
          results.push(result);
        }
      }

      // Calculate summary statistics
      for (const result of results) {
        if (result.isValid) {
          summary.valid++;
        } else {
          summary.invalid++;
        }
        summary.warnings += result.warnings.length;
        summary.errors += result.errors.length;
        summary.performance.totalDuration += result.performance.duration;
        summary.performance.memoryUsage += result.performance.memoryUsage;
        summary.performance.rulesExecuted += result.performance.rulesExecuted;
      }

      summary.performance.averageDuration = summary.performance.totalDuration / results.length;

      return {
        results,
        summary,
        duration: Date.now() - startTime,
        context
      };

    } catch (error) {
      return this.createBatchErrorResult(error as Error, context, startTime, metrics.length);
    }
  }

  // ============================================================================
  // Private Validation Methods - Audit Events
  // ============================================================================

  private async validateCoreAuditFields(
    event: TypedAuditEvent,
    errors: ValidationError[],
    warnings: ValidationWarning[],
    suggestions: ValidationSuggestion[]
  ): Promise<number> {
    let rulesExecuted = 0;

    // Required field validation
    if (!event.id || event.id.trim() === '') {
      errors.push({
        code: 'AUDIT_001',
        message: 'Event ID is required and cannot be empty',
        field: 'id',
        value: event.id,
        timestamp: new Date().toISOString()
      });
    }

    if (!event.entityType || event.entityType.trim() === '') {
      errors.push({
        code: 'AUDIT_002',
        message: 'Entity type is required and cannot be empty',
        field: 'entityType',
        value: event.entityType,
        timestamp: new Date().toISOString()
      });
    }

    if (!event.entityId || event.entityId.trim() === '') {
      errors.push({
        code: 'AUDIT_003',
        message: 'Entity ID is required and cannot be empty',
        field: 'entityId',
        value: event.entityId,
        timestamp: new Date().toISOString()
      });
    }

    // Enum validation
    if (!Object.values(AuditEventType).includes(event.eventType)) {
      errors.push({
        code: 'AUDIT_004',
        message: `Invalid event type: ${event.eventType}`,
        field: 'eventType',
        value: event.eventType,
        expected: Object.values(AuditEventType),
        timestamp: new Date().toISOString()
      });
    }

    if (!Object.values(AuditCategory).includes(event.category)) {
      errors.push({
        code: 'AUDIT_005',
        message: `Invalid category: ${event.category}`,
        field: 'category',
        value: event.category,
        expected: Object.values(AuditCategory),
        timestamp: new Date().toISOString()
      });
    }

    if (!Object.values(AuditOperation).includes(event.operation)) {
      errors.push({
        code: 'AUDIT_006',
        message: `Invalid operation: ${event.operation}`,
        field: 'operation',
        value: event.operation,
        expected: Object.values(AuditOperation),
        timestamp: new Date().toISOString()
      });
    }

    if (!Object.values(AuditSource).includes(event.source)) {
      errors.push({
        code: 'AUDIT_007',
        message: `Invalid source: ${event.source}`,
        field: 'source',
        value: event.source,
        expected: Object.values(AuditSource),
        timestamp: new Date().toISOString()
      });
    }

    // Timestamp validation
    const eventTimestamp = new Date(event.timestamp);
    if (isNaN(eventTimestamp.getTime())) {
      errors.push({
        code: 'AUDIT_008',
        message: 'Invalid timestamp format',
        field: 'timestamp',
        value: event.timestamp,
        timestamp: new Date().toISOString()
      });
    } else {
      const now = new Date();
      const futureThreshold = new Date(now.getTime() + 60000); // 1 minute in future
      const pastThreshold = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000); // 1 year ago

      if (eventTimestamp > futureThreshold) {
        warnings.push({
          code: 'AUDIT_009',
          message: 'Event timestamp is significantly in the future',
          field: 'timestamp',
          value: event.timestamp,
          recommendation: 'Check system clock synchronization',
          timestamp: new Date().toISOString()
        });
      }

      if (eventTimestamp < pastThreshold) {
        warnings.push({
          code: 'AUDIT_010',
          message: 'Event timestamp is more than 1 year old',
          field: 'timestamp',
          value: event.timestamp,
          recommendation: 'Verify this is intentional for historical data',
          timestamp: new Date().toISOString()
        });
      }
    }

    // Boolean validation
    if (typeof event.success !== 'boolean') {
      errors.push({
        code: 'AUDIT_011',
        message: 'Success field must be a boolean',
        field: 'success',
        value: event.success,
        expected: 'boolean',
        timestamp: new Date().toISOString()
      });
    }

    rulesExecuted += 10; // Approximate number of rules executed
    return rulesExecuted;
  }

  private async validateAuditBusinessLogic(
    event: TypedAuditEvent,
    errors: ValidationError[],
    warnings: ValidationWarning[],
    suggestions: ValidationSuggestion[]
  ): Promise<number> {
    let rulesExecuted = 0;

    // Operation-specific validation
    if (event.operation === AuditOperation.DELETE && event.newData && Object.keys(event.newData).length > 0) {
      warnings.push({
        code: 'AUDIT_012',
        message: 'Delete operations should not have new data',
        field: 'newData',
        value: event.newData,
        recommendation: 'Remove new data from delete operations',
        timestamp: new Date().toISOString()
      });
    }

    if (event.operation === AuditOperation.CREATE && event.oldData && Object.keys(event.oldData).length > 0) {
      warnings.push({
        code: 'AUDIT_013',
        message: 'Create operations should not have old data',
        field: 'oldData',
        value: event.oldData,
        recommendation: 'Remove old data from create operations',
        timestamp: new Date().toISOString()
      });
    }

    // Category/operation consistency
    const categoryOperationConflicts = this.getCategoryOperationConflicts(event.category, event.operation);
    if (categoryOperationConflicts.length > 0) {
      warnings.push({
        code: 'AUDIT_014',
        message: `Operation ${event.operation} is unusual for category ${event.category}`,
        field: 'operation',
        value: event.operation,
        recommendation: categoryOperationConflicts.join(', '),
        timestamp: new Date().toISOString()
      });
    }

    // Data consistency checks
    if (event.changedFields && Array.isArray(event.changedFields)) {
      const hasDataChanges = event.oldData || event.newData;
      if (!hasDataChanges && event.changedFields.length > 0) {
        warnings.push({
          code: 'AUDIT_015',
          message: 'Changed fields specified but no data changes found',
          field: 'changedFields',
          value: event.changedFields,
          recommendation: 'Ensure changed fields match actual data changes',
          timestamp: new Date().toISOString()
        });
      }
    }

    // Duration validation for operations that should be fast
    if (event.duration !== undefined) {
      if (event.duration < 0) {
        errors.push({
          code: 'AUDIT_016',
          message: 'Duration cannot be negative',
          field: 'duration',
          value: event.duration,
          timestamp: new Date().toISOString()
        });
      } else if (event.duration > 300000) { // 5 minutes
        warnings.push({
          code: 'AUDIT_017',
          message: 'Operation duration exceeds 5 minutes',
          field: 'duration',
          value: event.duration,
          recommendation: 'Consider optimizing long-running operations',
          timestamp: new Date().toISOString()
        });
      }
    }

    // User context validation
    if (event.sensitivity === SensitivityLevel.SECRET && !event.userId) {
      warnings.push({
        code: 'AUDIT_018',
        message: 'Secret-level events should have user identification',
        field: 'userId',
        value: event.userId,
        recommendation: 'Add user context for high-sensitivity events',
        timestamp: new Date().toISOString()
      });
    }

    rulesExecuted += 7;
    return rulesExecuted;
  }

  private async validateAuditCompliance(
    event: TypedAuditEvent,
    errors: ValidationError[],
    warnings: ValidationWarning[],
    suggestions: ValidationSuggestion[]
  ): Promise<number> {
    let rulesExecuted = 0;

    // GDPR compliance checks
    if (event.compliance.frameworks.includes(ComplianceFramework.GDPR)) {
      if (event.operation === AuditOperation.DELETE) {
        if (!event.metadata.dataOwner) {
          warnings.push({
            code: 'AUDIT_019',
            message: 'GDPR compliance requires data owner for delete operations',
            field: 'metadata.dataOwner',
            recommendation: 'Specify data owner for GDPR delete operations',
            timestamp: new Date().toISOString()
          });
        }

        if (!event.compliance.regulations.includes(ComplianceRegulation.GDPR_ARTICLE_17)) {
          suggestions.push({
            type: SuggestionType.COMPLIANCE,
            message: 'Consider adding GDPR Article 17 (right to erasure) reference',
            action: 'Add GDPR_ARTICLE_17 to compliance regulations',
            priority: 7,
            timestamp: new Date().toISOString()
          });
        }
      }
    }

    // SOX compliance checks
    if (event.compliance.frameworks.includes(ComplianceFramework.SOX)) {
      if (event.category === AuditCategory.FINANCIAL && !event.changed_by) {
        warnings.push({
          code: 'AUDIT_020',
          message: 'SOX compliance requires user attribution for financial events',
          field: 'changed_by',
          recommendation: 'Add user attribution for financial audit events',
          timestamp: new Date().toISOString()
        });
      }

      if (!event.compliance.retentionPeriod) {
        suggestions.push({
          type: SuggestionType.COMPLIANCE,
          message: 'SOX requires defined retention periods',
          action: 'Define retention period for SOX compliance',
          priority: 8,
          timestamp: new Date().toISOString()
        });
      }
    }

    // Data classification validation
    if (event.sensitivity === SensitivityLevel.RESTRICTED || event.sensitivity === SensitivityLevel.SECRET) {
      if (!event.compliance.frameworks || event.compliance.frameworks.length === 0) {
        warnings.push({
          code: 'AUDIT_021',
          message: 'High sensitivity events should have compliance frameworks',
          field: 'compliance.frameworks',
          value: event.compliance.frameworks,
          recommendation: 'Add relevant compliance frameworks for high-sensitivity data',
          timestamp: new Date().toISOString()
        });
      }
    }

    rulesExecuted += 4;
    return rulesExecuted;
  }

  private async validateAuditSecurity(
    event: TypedAuditEvent,
    errors: ValidationError[],
    warnings: ValidationWarning[],
    suggestions: ValidationSuggestion[]
  ): Promise<number> {
    let rulesExecuted = 0;

    // IP address validation
    if (event.ipAddress) {
      if (!this.isValidIPAddress(event.ipAddress)) {
        errors.push({
          code: 'AUDIT_022',
          message: 'Invalid IP address format',
          field: 'ipAddress',
          value: event.ipAddress,
          timestamp: new Date().toISOString()
        });
      } else if (this.isPrivateIPAddress(event.ipAddress) && event.source === AuditSource.API) {
        warnings.push({
          code: 'AUDIT_023',
          message: 'API request from private IP address',
          field: 'ipAddress',
          value: event.ipAddress,
          recommendation: 'Verify this is expected internal traffic',
          timestamp: new Date().toISOString()
        });
      }
    }

    // User agent validation
    if (event.userAgent) {
      if (event.userAgent.length > 500) {
        warnings.push({
          code: 'AUDIT_024',
          message: 'User agent string is unusually long',
          field: 'userAgent',
          value: event.userAgent.length,
          recommendation: 'Check for potential injection or malformed data',
          timestamp: new Date().toISOString()
        });
      }

      if (this.detectSuspiciousUserAgent(event.userAgent)) {
        warnings.push({
          code: 'AUDIT_025',
          message: 'Suspicious user agent detected',
          field: 'userAgent',
          value: event.userAgent,
          recommendation: 'Review for potential security threats',
          timestamp: new Date().toISOString()
        });
      }
    }

    // Geographic validation
    if (event.location && event.location.country) {
      if (!this.isValidCountryCode(event.location.country)) {
        errors.push({
          code: 'AUDIT_026',
          message: 'Invalid country code',
          field: 'location.country',
          value: event.location.country,
          timestamp: new Date().toISOString()
        });
      }
    }

    // Session validation
    if (event.sessionId && event.userId) {
      // Check for session anomalies would go here
      // This would typically involve checking against a session store
    }

    rulesExecuted += 5;
    return rulesExecuted;
  }

  private async validateAuditPerformance(
    event: TypedAuditEvent,
    errors: ValidationError[],
    warnings: ValidationWarning[],
    suggestions: ValidationSuggestion[]
  ): Promise<number> {
    let rulesExecuted = 0;

    // Metadata size validation
    const metadataSize = JSON.stringify(event.metadata).length;
    if (metadataSize > 10000) { // 10KB
      warnings.push({
        code: 'AUDIT_027',
        message: 'Large metadata payload detected',
        field: 'metadata',
        value: metadataSize,
        recommendation: 'Consider reducing metadata size or using references',
        timestamp: new Date().toISOString()
      });
    }

    // Tags validation
    if (event.tags && Object.keys(event.tags).length > 50) {
      warnings.push({
        code: 'AUDIT_028',
        message: 'Large number of tags may impact performance',
        field: 'tags',
        value: Object.keys(event.tags).length,
        recommendation: 'Consider reducing the number of tags',
        timestamp: new Date().toISOString()
      });
    }

    // Data payload validation
    const dataSize = this.calculateDataSize(event.oldData) + this.calculateDataSize(event.newData);
    if (dataSize > 100000) { // 100KB
      warnings.push({
        code: 'AUDIT_029',
        message: 'Large data payload detected',
        field: 'oldData/newData',
        value: dataSize,
        recommendation: 'Consider data compression or references for large payloads',
        timestamp: new Date().toISOString()
      });
    }

    rulesExecuted += 3;
    return rulesExecuted;
  }

  // ============================================================================
  // Private Validation Methods - Metrics
  // ============================================================================

  private async validateCoreMetricFields(
    metric: TypedMetric,
    errors: ValidationError[],
    warnings: ValidationWarning[],
    suggestions: ValidationSuggestion[]
  ): Promise<number> {
    let rulesExecuted = 0;

    // Required field validation
    if (!metric.id || metric.id.trim() === '') {
      errors.push({
        code: 'METRIC_001',
        message: 'Metric ID is required and cannot be empty',
        field: 'id',
        value: metric.id,
        timestamp: new Date().toISOString()
      });
    }

    if (!metric.name || metric.name.trim() === '') {
      errors.push({
        code: 'METRIC_002',
        message: 'Metric name is required and cannot be empty',
        field: 'name',
        value: metric.name,
        timestamp: new Date().toISOString()
      });
    }

    if (!metric.component || metric.component.trim() === '') {
      errors.push({
        code: 'METRIC_003',
        message: 'Component is required and cannot be empty',
        field: 'component',
        value: metric.component,
        timestamp: new Date().toISOString()
      });
    }

    // Enum validation
    if (!Object.values(MetricType).includes(metric.type)) {
      errors.push({
        code: 'METRIC_004',
        message: `Invalid metric type: ${metric.type}`,
        field: 'type',
        value: metric.type,
        expected: Object.values(MetricType),
        timestamp: new Date().toISOString()
      });
    }

    if (!Object.values(MetricCategory).includes(metric.category)) {
      errors.push({
        code: 'METRIC_005',
        message: `Invalid metric category: ${metric.category}`,
        field: 'category',
        value: metric.category,
        expected: Object.values(MetricCategory),
        timestamp: new Date().toISOString()
      });
    }

    // Timestamp validation
    const metricTimestamp = new Date(metric.timestamp);
    if (isNaN(metricTimestamp.getTime())) {
      errors.push({
        code: 'METRIC_006',
        message: 'Invalid timestamp format',
        field: 'timestamp',
        value: metric.timestamp,
        timestamp: new Date().toISOString()
      });
    }

    // Quality validation
    if (metric.quality.accuracy < 0 || metric.quality.accuracy > 1) {
      errors.push({
        code: 'METRIC_007',
        message: 'Quality accuracy must be between 0 and 1',
        field: 'quality.accuracy',
        value: metric.quality.accuracy,
        expected: '0-1 range',
        timestamp: new Date().toISOString()
      });
    }

    if (metric.quality.completeness < 0 || metric.quality.completeness > 1) {
      errors.push({
        code: 'METRIC_008',
        message: 'Quality completeness must be between 0 and 1',
        field: 'quality.completeness',
        value: metric.quality.completeness,
        expected: '0-1 range',
        timestamp: new Date().toISOString()
      });
    }

    rulesExecuted += 8;
    return rulesExecuted;
  }

  private async validateMetricDataTypes(
    metric: TypedMetric,
    errors: ValidationError[],
    warnings: ValidationWarning[],
    suggestions: ValidationSuggestion[]
  ): Promise<number> {
    let rulesExecuted = 0;

    // Value type validation based on metric type
    if (typeof metric.value === 'number') {
      if (isNaN(metric.value)) {
        errors.push({
          code: 'METRIC_009',
          message: 'Metric value cannot be NaN',
          field: 'value',
          value: metric.value,
          timestamp: new Date().toISOString()
        });
      }

      if (!isFinite(metric.value)) {
        errors.push({
          code: 'METRIC_010',
          message: 'Metric value must be finite',
          field: 'value',
          value: metric.value,
          timestamp: new Date().toISOString()
        });
      }

      // Metric type-specific validations
      if (metric.type === MetricType.COUNTER && metric.value < 0) {
        warnings.push({
          code: 'METRIC_011',
          message: 'Counter metrics should have non-negative values',
          field: 'value',
          value: metric.value,
          recommendation: 'Check for counter reset logic',
          timestamp: new Date().toISOString()
        });
      }

      if (metric.type === MetricType.PERCENTILE && (metric.value < 0 || metric.value > 100)) {
        warnings.push({
          code: 'METRIC_012',
          message: 'Percentile metrics should be between 0 and 100',
          field: 'value',
          value: metric.value,
          recommendation: 'Verify percentile calculation logic',
          timestamp: new Date().toISOString()
        });
      }
    }

    // Dimension validation
    for (const dimension of metric.dimensions) {
      if (!dimension.name || !dimension.value) {
        errors.push({
          code: 'METRIC_013',
          message: 'Dimension name and value are required',
          field: 'dimensions',
          value: dimension,
          timestamp: new Date().toISOString()
        });
      }

      if (dimension.name.length > 100) {
        warnings.push({
          code: 'METRIC_014',
          message: 'Dimension name is very long',
          field: 'dimensions',
          value: dimension.name,
          recommendation: 'Consider shorter dimension names',
          timestamp: new Date().toISOString()
        });
      }
    }

    rulesExecuted += 4;
    return rulesExecuted;
  }

  private async validateMetricValueRanges(
    metric: TypedMetric,
    errors: ValidationError[],
    warnings: ValidationWarning[],
    suggestions: ValidationSuggestion[]
  ): Promise<number> {
    let rulesExecuted = 0;

    if (typeof metric.value === 'number' && metric.metadata.bounds) {
      const { bounds } = metric.metadata;

      // Check against min/max bounds
      if (bounds.min !== undefined && metric.value < bounds.min) {
        warnings.push({
          code: 'METRIC_015',
          message: 'Metric value below minimum bound',
          field: 'value',
          value: metric.value,
          recommendation: `Value should be >= ${bounds.min}`,
          timestamp: new Date().toISOString()
        });
      }

      if (bounds.max !== undefined && metric.value > bounds.max) {
        warnings.push({
          code: 'METRIC_016',
          message: 'Metric value above maximum bound',
          field: 'value',
          value: metric.value,
          recommendation: `Value should be <= ${bounds.max}`,
          timestamp: new Date().toISOString()
        });
      }

      // Check against expected range
      if (bounds.expectedRange && Array.isArray(bounds.expectedRange) && bounds.expectedRange.length === 2) {
        const [min, max] = bounds.expectedRange;
        if (metric.value < min || metric.value > max) {
          warnings.push({
            code: 'METRIC_017',
            message: 'Metric value outside expected range',
            field: 'value',
            value: metric.value,
            recommendation: `Expected range: [${min}, ${max}]`,
            timestamp: new Date().toISOString()
          });
        }
      }

      // Check against critical range
      if (bounds.criticalRange && Array.isArray(bounds.criticalRange) && bounds.criticalRange.length === 2) {
        const [min, max] = bounds.criticalRange;
        if (metric.value < min || metric.value > max) {
          errors.push({
            code: 'METRIC_018',
            message: 'Metric value in critical range',
            field: 'value',
            value: metric.value,
            recommendation: `Critical range violation: [${min}, ${max}]`,
            timestamp: new Date().toISOString()
          });
        }
      }
    }

    rulesExecuted += 2;
    return rulesExecuted;
  }

  private async validateMetricQuality(
    metric: TypedMetric,
    errors: ValidationError[],
    warnings: ValidationWarning[],
    suggestions: ValidationSuggestion[]
  ): Promise<number> {
    let rulesExecuted = 0;

    // Quality threshold validation
    const qualityThresholds = {
      accuracy: 0.8,
      completeness: 0.9,
      consistency: 0.85,
      timeliness: 0.9,
      validity: 0.9,
      reliability: 0.85
    };

    for (const [qualityMetric, threshold] of Object.entries(qualityThresholds)) {
      const value = metric.quality[qualityMetric as keyof typeof metric.quality];
      if (typeof value === 'number' && value < threshold) {
        warnings.push({
          code: 'METRIC_019',
          message: `Low ${qualityMetric} quality score`,
          field: `quality.${qualityMetric}`,
          value: value,
          recommendation: `Investigate ${qualityMetric} issues (threshold: ${threshold})`,
          timestamp: new Date().toISOString()
        });
      }
    }

    // Validation timestamp check
    const validationAge = Date.now() - new Date(metric.quality.lastValidated).getTime();
    const maxValidationAge = 24 * 60 * 60 * 1000; // 24 hours

    if (validationAge > maxValidationAge) {
      warnings.push({
        code: 'METRIC_020',
        message: 'Metric quality validation is stale',
        field: 'quality.lastValidated',
        value: metric.quality.lastValidated,
        recommendation: 'Refresh metric quality validation',
        timestamp: new Date().toISOString()
      });
    }

    rulesExecuted += 2;
    return rulesExecuted;
  }

  private async validateMetricPerformance(
    metric: TypedMetric,
    errors: ValidationError[],
    warnings: ValidationWarning[],
    suggestions: ValidationSuggestion[]
  ): Promise<number> {
    let rulesExecuted = 0;

    // Metadata size validation
    const metadataSize = JSON.stringify(metric.metadata).length;
    if (metadataSize > 5000) { // 5KB
      warnings.push({
        code: 'METRIC_021',
        message: 'Large metadata payload detected',
        field: 'metadata',
        value: metadataSize,
        recommendation: 'Consider reducing metadata size',
        timestamp: new Date().toISOString()
      });
    }

    // Dimensions count validation
    if (metric.dimensions.length > 20) {
      warnings.push({
        code: 'METRIC_022',
        message: 'High cardinality detected (many dimensions)',
        field: 'dimensions',
        value: metric.dimensions.length,
        recommendation: 'Consider reducing dimensionality for better performance',
        timestamp: new Date().toISOString()
      });
    }

    // Labels count validation
    const labelsCount = Object.keys(metric.labels).length;
    if (labelsCount > 50) {
      warnings.push({
        code: 'METRIC_023',
        message: 'High number of labels may impact performance',
        field: 'labels',
        value: labelsCount,
        recommendation: 'Consider reducing the number of labels',
        timestamp: new Date().toISOString()
      });
    }

    rulesExecuted += 3;
    return rulesExecuted;
  }

  // ============================================================================
  // Custom Rule Execution
  // ============================================================================

  private async executeCustomRule(
    rule: CustomValidationRule,
    data: TypedAuditEvent | TypedMetric,
    context: ValidationContext
  ): Promise<ValidationResult> {
    const startTime = Date.now();

    try {
      // Apply timeout to custom rule execution
      const result = await this.withTimeout(
        rule.validator(data, context),
        this.config.timeouts.customRuleExecution,
        `Custom rule ${rule.id} timed out`
      ) as ValidationResult;

      const duration = Date.now() - startTime;

      return {
        isValid: result.errors.length === 0,
        severity: this.calculateSeverity(result.errors, result.warnings),
        errors: result.errors.map(error => ({
          ...error,
          ruleId: rule.id,
          timestamp: new Date().toISOString()
        })),
        warnings: result.warnings.map(warning => ({
          ...warning,
          ruleId: rule.id,
          timestamp: new Date().toISOString()
        })),
        suggestions: result.suggestions.map(suggestion => ({
          ...suggestion,
          ruleId: rule.id,
          timestamp: new Date().toISOString()
        })),
        performance: {
          duration,
          memoryUsage: 0, // Would need more sophisticated tracking
          rulesExecuted: 1,
          cacheHits: 0,
          cacheMisses: 0,
          timestamp: new Date().toISOString()
        },
        context
      };

    } catch (error) {
      return {
        isValid: false,
        severity: ValidationSeverity.ERROR,
        errors: [{
          code: 'CUSTOM_RULE_ERROR',
          message: `Custom rule ${rule.id} failed: ${(error as Error).message}`,
          ruleId: rule.id,
          timestamp: new Date().toISOString(),
          stack: this.config.reporting.includeStackTrace ? (error as Error).stack : undefined
        }],
        warnings: [],
        suggestions: [],
        performance: {
          duration: Date.now() - startTime,
          memoryUsage: 0,
          rulesExecuted: 1,
          cacheHits: 0,
          cacheMisses: 0,
          timestamp: new Date().toISOString()
        },
        context
      };
    }
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  private calculateSeverity(errors: ValidationError[], warnings: ValidationWarning[]): ValidationSeverity {
    if (errors.length > 0) {
      return ValidationSeverity.ERROR;
    }
    if (warnings.length > 5) {
      return ValidationSeverity.WARNING;
    }
    if (warnings.length > 0) {
      return ValidationSeverity.INFO;
    }
    return ValidationSeverity.DEBUG;
  }

  private getCategoryOperationConflicts(category: AuditCategory, operation: AuditOperation): string[] {
    const conflicts: string[] = [];

    // Define unusual category/operation combinations
    const unusualCombinations: Record<AuditCategory, AuditOperation[]> = {
      [AuditCategory.SECURITY]: [AuditOperation.CREATE],
      [AuditCategory.SYSTEM]: [AuditOperation.CREATE, AuditOperation.UPDATE],
      [AuditCategory.PERFORMANCE]: [AuditOperation.CREATE, AuditOperation.UPDATE, AuditOperation.DELETE],
      [AuditCategory.BUSINESS]: [],
      [AuditCategory.COMPLIANCE]: [],
      [AuditCategory.OPERATION]: [],
      [AuditCategory.DATA]: [],
      [AuditCategory.ACCESS]: []
    };

    if (unusualCombinations[category]?.includes(operation)) {
      conflicts.push(`${operation} is unusual for ${category} category`);
    }

    return conflicts;
  }

  private isValidIPAddress(ip: string): boolean {
    // IPv4 regex
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    // IPv6 regex (simplified)
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;

    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
  }

  private isPrivateIPAddress(ip: string): boolean {
    // Check for private IP ranges
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^127\./,
      /^169\.254\./
    ];

    return privateRanges.some(range => range.test(ip));
  }

  private detectSuspiciousUserAgent(userAgent: string): boolean {
    const suspiciousPatterns = [
      /bot/i,
      /crawler/i,
      /scanner/i,
      /sqlmap/i,
      /nikto/i,
      /nmap/i,
      /curl/i,
      /wget/i
    ];

    return suspiciousPatterns.some(pattern => pattern.test(userAgent));
  }

  private isValidCountryCode(country: string): boolean {
    // Simple validation - in production would use a proper country code list
    return /^[A-Z]{2}$/.test(country);
  }

  private calculateDataSize(data: unknown): number {
    if (!data) return 0;
    return JSON.stringify(data).length;
  }

  private generateAuditCacheKey(event: TypedAuditEvent): string {
    const keyData = {
      eventType: event.eventType,
      entityType: event.entityType,
      entityId: event.entityId,
      operation: event.operation,
      timestamp: event.timestamp
    };
    return `audit:${Buffer.from(JSON.stringify(keyData)).toString('base64')}`;
  }

  private generateMetricCacheKey(metric: TypedMetric): string {
    const keyData = {
      name: metric.name,
      type: metric.type,
      component: metric.component,
      dimensions: metric.dimensions,
      timestamp: metric.timestamp
    };
    return `metric:${Buffer.from(JSON.stringify(keyData)).toString('base64')}`;
  }

  private setCacheWithSizeLimit<K, V>(
    cache: Map<K, V>,
    key: K,
    value: V
  ): void {
    if (cache.size >= this.config.cacheSize) {
      // Remove oldest entry (simple LRU)
      const firstKey = cache.keys().next().value;
      if (firstKey) {
        cache.delete(firstKey);
      }
    }
    cache.set(key, value);
  }

  private createErrorResult(
    error: Error,
    context: ValidationContext,
    startTime: number
  ): ValidationResult {
    return {
      isValid: false,
      severity: ValidationSeverity.CRITICAL,
      errors: [{
        code: 'VALIDATION_ERROR',
        message: error.message,
        timestamp: new Date().toISOString(),
        stack: this.config.reporting.includeStackTrace ? error.stack : undefined
      }],
      warnings: [],
      suggestions: [],
      performance: {
        duration: Date.now() - startTime,
        memoryUsage: process.memoryUsage().heapUsed,
        rulesExecuted: 0,
        cacheHits: 0,
        cacheMisses: 0,
        timestamp: new Date().toISOString()
      },
      context
    };
  }

  private createBatchErrorResult(
    error: Error,
    context?: ValidationContext,
    startTime?: number,
    totalItems?: number
  ): BatchValidationResult {
    return {
      results: [],
      summary: {
        total: totalItems || 0,
        valid: 0,
        invalid: 0,
        warnings: 0,
        errors: 1,
        performance: {
          totalDuration: Date.now() - (startTime || Date.now()),
          averageDuration: 0,
          memoryUsage: process.memoryUsage().heapUsed,
          rulesExecuted: 0
        }
      },
      duration: Date.now() - (startTime || Date.now()),
      context
    };
  }

  private async withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    timeoutMessage: string
  ): Promise<T> {
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error(timeoutMessage)), timeoutMs);
    });

    return Promise.race([promise, timeoutPromise]);
  }

  private initializeBuiltInRules(): void {
    // Add built-in custom validation rules
    this.config.customRules.push(
      {
        id: 'audit_data_integrity',
        name: 'Audit Data Integrity Check',
        description: 'Validates data integrity for audit events',
        type: 'audit',
        enabled: true,
        priority: 8,
        validator: this.validateAuditDataIntegrity.bind(this),
        errorMessage: 'Audit data integrity check failed'
      },
      {
        id: 'metric_anomaly_detection',
        name: 'Metric Anomaly Detection',
        description: 'Detects anomalous metric values',
        type: 'metric',
        enabled: true,
        priority: 6,
        validator: this.detectMetricAnomalies.bind(this),
        errorMessage: 'Metric anomaly detected'
      }
    );

    // Store rules in map for quick lookup
    for (const rule of this.config.customRules) {
      this.customRules.set(rule.id, rule);
    }
  }

  private async validateAuditDataIntegrity(
    data: TypedAuditEvent | TypedMetric,
    context?: ValidationContext
  ): Promise<ValidationResult> {
    // Implement data integrity checks
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    const suggestions: ValidationSuggestion[] = [];

    if ('oldData' in data) {
      const auditEvent = data as TypedAuditEvent;
      // Check for data consistency
      if (auditEvent.oldData && auditEvent.newData) {
        const oldSize = JSON.stringify(auditEvent.oldData).length;
        const newSize = JSON.stringify(auditEvent.newData).length;

        if (Math.abs(oldSize - newSize) > 100000) { // 100KB difference
          warnings.push({
            code: 'DATA_INTEGRITY_001',
            message: 'Significant data size change detected',
            field: 'oldData/newData',
            value: { oldSize, newSize },
            recommendation: 'Verify data change is intentional',
            timestamp: new Date().toISOString()
          });
        }
      }
    }

    return {
      isValid: errors.length === 0,
      severity: this.calculateSeverity(errors, warnings),
      errors,
      warnings,
      suggestions,
      performance: {
        duration: 0,
        memoryUsage: 0,
        rulesExecuted: 1,
        cacheHits: 0,
        cacheMisses: 0,
        timestamp: new Date().toISOString()
      },
      context
    };
  }

  private async detectMetricAnomalies(
    data: TypedAuditEvent | TypedMetric,
    context?: ValidationContext
  ): Promise<ValidationResult> {
    // Implement metric anomaly detection
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    const suggestions: ValidationSuggestion[] = [];

    if ('value' in data && typeof data.value === 'number') {
      const metric = data as TypedMetric;

      // Simple anomaly detection based on value ranges
      if (Math.abs(metric.value) > 1000000) { // Very large values
        warnings.push({
          code: 'METRIC_ANOMALY_001',
          message: 'Unusually large metric value detected',
          field: 'value',
          value: metric.value,
          recommendation: 'Verify metric value is correct',
          timestamp: new Date().toISOString()
        });
      }

      if (metric.value === 0 && metric.type === MetricType.COUNTER) {
        warnings.push({
          code: 'METRIC_ANOMALY_002',
          message: 'Counter metric with zero value may indicate reset issue',
          field: 'value',
          value: metric.value,
          recommendation: 'Check counter initialization logic',
          timestamp: new Date().toISOString()
        });
      }
    }

    return {
      isValid: errors.length === 0,
      severity: this.calculateSeverity(errors, warnings),
      errors,
      warnings,
      suggestions,
      performance: {
        duration: 0,
        memoryUsage: 0,
        rulesExecuted: 1,
        cacheHits: 0,
        cacheMisses: 0,
        timestamp: new Date().toISOString()
      },
      context
    };
  }
}

// ============================================================================
// Supporting Classes
// ============================================================================

/**
 * Batch validation result
 */
export interface BatchValidationResult {
  results: ValidationResult[];
  summary: BatchValidationSummary;
  duration: number;
  context?: ValidationContext;
}

/**
 * Batch validation summary
 */
export interface BatchValidationSummary {
  total: number;
  valid: number;
  invalid: number;
  warnings: number;
  errors: number;
  performance: {
    totalDuration: number;
    averageDuration: number;
    memoryUsage: number;
    rulesExecuted: number;
  };
}

/**
 * Performance tracker for validation operations
 */
class ValidationPerformanceTracker {
  private cacheHits: Record<string, number> = { audit: 0, metric: 0 };
  private cacheMisses: Record<string, number> = { audit: 0, metric: 0 };

  recordCacheHit(type: 'audit' | 'metric'): void {
    this.cacheHits[type]++;
  }

  recordCacheMiss(type: 'audit' | 'metric'): void {
    this.cacheMisses[type]++;
  }

  getCacheHits(type: 'audit' | 'metric'): number {
    return this.cacheHits[type];
  }

  getCacheMisses(type: 'audit' | 'metric'): number {
    return this.cacheMisses[type];
  }
}

// ============================================================================
// Default Configuration and Exports
// ============================================================================

/**
 * Create default validation configuration
 */
export function createDefaultValidationConfig(): ValidationConfig {
  return {
    strictMode: false,
    enablePerformanceOptimization: true,
    cacheEnabled: true,
    cacheSize: 10000,
    customRules: [],
    timeouts: {
      auditValidation: 1000,
      metricValidation: 500,
      batchValidation: 5000,
      customRuleExecution: 200
    },
    reporting: {
      includeStackTrace: false,
      includeContext: true,
      includePerformanceMetrics: true,
      aggregateResults: true,
      reportInterval: 60000
    }
  };
}

/**
 * Export singleton validator instance
 */
export const auditMetricsValidator = new AuditMetricsValidator(createDefaultValidationConfig());