/**
 * Canary Configuration Validator
 *
 * Provides comprehensive configuration validation with:
 * - Schema validation for all canary configurations
 * - Cross-service dependency validation
 * - Resource availability checks
 * - Security constraint validation
 * - Performance requirement validation
 * - Configuration consistency checks
 * - Best practice enforcement
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { logger } from '@/utils/logger.js';

import { type CanaryHealthConfig } from './canary-health-monitor.js';
import { type CanaryDeploymentConfig, type DeploymentPhase } from './canary-orchestrator.js';
import { type KillSwitchConfig } from './kill-switch-service.js';
import { type RollbackConfig } from './rollback-service.js';
import { type TrafficRule } from './traffic-splitter.js';
import { type FeatureFlag } from '../feature-flag/feature-flag-service.js';

// ============================================================================
// Types and Interfaces
// ============================================================================

/**
 * Validation severity levels
 */
export enum ValidationSeverity {
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
  CRITICAL = 'critical',
}

/**
 * Validation result
 */
export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
  info: ValidationInfo[];
  summary: {
    totalIssues: number;
    criticalIssues: number;
    errorIssues: number;
    warningIssues: number;
    infoIssues: number;
  };
  recommendations: string[];
  validatedAt: Date;
}

/**
 * Validation error
 */
export interface ValidationError {
  id: string;
  code: string;
  message: string;
  field?: string;
  value?: unknown;
  expectedValue?: unknown;
  severity: ValidationSeverity;
  category: ValidationCategory;
  fixable: boolean;
  fixSuggestion?: string;
}

/**
 * Validation warning
 */
export interface ValidationWarning {
  id: string;
  code: string;
  message: string;
  field?: string;
  value?: unknown;
  recommendedValue?: unknown;
  severity: ValidationSeverity;
  category: ValidationCategory;
  actionable: boolean;
  actionSuggestion?: string;
}

/**
 * Validation info
 */
export interface ValidationInfo {
  id: string;
  code: string;
  message: string;
  field?: string;
  value?: unknown;
  severity: ValidationSeverity;
  category: ValidationCategory;
  bestPractice: boolean;
  reference?: string;
}

/**
 * Validation categories
 */
export enum ValidationCategory {
  SCHEMA = 'schema',
  SECURITY = 'security',
  PERFORMANCE = 'performance',
  RELIABILITY = 'reliability',
  SCALABILITY = 'scalability',
  MONITORING = 'monitoring',
  NETWORK = 'network',
  RESOURCE = 'resource',
  COMPLIANCE = 'compliance',
  BEST_PRACTICE = 'best_practice',
}

/**
 * Configuration validation request
 */
export interface ValidationRequest {
  type:
    | 'canary_deployment'
    | 'health_monitor'
    | 'rollback'
    | 'traffic_rule'
    | 'kill_switch'
    | 'feature_flag';
  config: unknown;
  context?: ValidationContext;
  strictMode?: boolean;
}

/**
 * Validation context
 */
export interface ValidationContext {
  environment?: string;
  region?: string;
  cluster?: string;
  namespace?: string;
  serviceDependencies?: string[];
  resourceConstraints?: ResourceConstraints;
  securityPolicies?: SecurityPolicy[];
  complianceRequirements?: ComplianceRequirement[];
}

/**
 * Resource constraints
 */
export interface ResourceConstraints {
  maxMemoryPerInstance?: number;
  maxCPUPerInstance?: number;
  maxInstances?: number;
  maxTrafficPercentage?: number;
  maxRollbackTime?: number;
}

/**
 * Security policy
 */
export interface SecurityPolicy {
  name: string;
  rules: SecurityRule[];
}

/**
 * Security rule
 */
export interface SecurityRule {
  type: 'encryption' | 'authentication' | 'authorization' | 'network' | 'data';
  required: boolean;
  config?: Record<string, unknown>;
}

/**
 * Compliance requirement
 */
export interface ComplianceRequirement {
  standard: string;
  requirements: ComplianceRule[];
}

/**
 * Compliance rule
 */
export interface ComplianceRule {
  control: string;
  required: boolean;
  validation: string;
}

/**
 * Validation rule
 */
export interface ValidationRule {
  name: string;
  category: ValidationCategory;
  severity: ValidationSeverity;
  validator: (config: unknown, context?: ValidationContext) => ValidationResult;
}

/**
 * Health threshold configuration
 */
export interface HealthThreshold {
  warning: number;
  critical: number;
  windowSize: number;
  metric: string;
}

/**
 * Action configuration for validation
 */
export interface ActionConfig {
  type: string;
  order: number;
  timeoutMs: number;
  config?: Record<string, unknown>;
  dependencies?: string[];
}

/**
 * Target configuration for validation
 */
export interface TargetConfig {
  id: string;
  name: string;
  endpoint: string;
  weight: number;
  healthy: boolean;
}

// ============================================================================
// Configuration Validator Implementation
// ============================================================================

/**
 * Main configuration validator
 */
export class CanaryConfigValidator {
  private validationRules: Map<string, ValidationRule[]> = new Map();
  private schemas: Map<string, unknown> = new Map();

  constructor() {
    this.initializeValidationRules();
    this.initializeSchemas();
    logger.info('Canary Configuration Validator initialized');
  }

  // ============================================================================
  // Main Validation Methods
  // ============================================================================

  /**
   * Validate configuration
   */
  validate(request: ValidationRequest): ValidationResult {
    const startTime = Date.now();
    const context = request.context || {};

    logger.debug('Starting configuration validation', {
      type: request.type,
      strictMode: request.strictMode,
    });

    let result: ValidationResult;

    try {
      switch (request.type) {
        case 'canary_deployment':
          result = this.validateCanaryDeploymentConfig(
            request.config as CanaryDeploymentConfig,
            context
          );
          break;
        case 'health_monitor':
          result = this.validateHealthMonitorConfig(request.config as CanaryHealthConfig, context);
          break;
        case 'rollback':
          result = this.validateRollbackConfig(request.config as RollbackConfig, context);
          break;
        case 'traffic_rule':
          result = this.validateTrafficRuleConfig(request.config as TrafficRule, context);
          break;
        case 'kill_switch':
          result = this.validateKillSwitchConfig(request.config as KillSwitchConfig, context);
          break;
        case 'feature_flag':
          result = this.validateFeatureFlagConfig(request.config as FeatureFlag, context);
          break;
        default:
          result = this.createErrorResult(`Unknown configuration type: ${request.type}`);
      }

      // Apply strict mode if enabled
      if (request.strictMode) {
        result = this.applyStrictMode(result);
      }

      // Add validation metadata
      result.validatedAt = new Date();

      const validationTime = Date.now() - startTime;
      logger.debug('Configuration validation completed', {
        type: request.type,
        valid: result.valid,
        totalIssues: result.summary.totalIssues,
        criticalIssues: result.summary.criticalIssues,
        validationTime,
      });

      return result;
    } catch (error) {
      logger.error('Error during configuration validation', {
        type: request.type,
        error: error instanceof Error ? error.message : String(error),
      });

      return this.createErrorResult(
        `Validation error: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Validate canary deployment configuration
   */
  private validateCanaryDeploymentConfig(
    config: CanaryDeploymentConfig,
    context: ValidationContext
  ): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    const info: ValidationInfo[] = [];

    // Basic field validation
    this.validateRequiredFields(
      config,
      [
        'name',
        'serviceName',
        'stableVersion',
        'canaryVersion',
        'initialTrafficPercentage',
        'targetTrafficPercentage',
        'phases',
        'healthCheckIntervalMs',
      ],
      errors,
      'canary_deployment'
    );

    // Version validation
    if (config.stableVersion === config.canaryVersion) {
      errors.push(
        this.createError(
          'versions_identical',
          'Stable and canary versions must be different',
          'canaryVersion',
          config.canaryVersion,
          'different version',
          ValidationCategory.SCHEMA
        )
      );
    }

    // Traffic percentage validation
    if (config.initialTrafficPercentage < 0 || config.initialTrafficPercentage > 100) {
      errors.push(
        this.createError(
          'invalid_initial_traffic',
          'Initial traffic percentage must be between 0 and 100',
          'initialTrafficPercentage',
          config.initialTrafficPercentage as number,
          '0-100',
          ValidationCategory.SCHEMA
        )
      );
    }

    if (config.targetTrafficPercentage < 0 || config.targetTrafficPercentage > 100) {
      errors.push(
        this.createError(
          'invalid_target_traffic',
          'Target traffic percentage must be between 0 and 100',
          'targetTrafficPercentage',
          config.targetTrafficPercentage,
          '0-100',
          ValidationCategory.SCHEMA
        )
      );
    }

    if (config.targetTrafficPercentage < config.initialTrafficPercentage) {
      errors.push(
        this.createError(
          'traffic_progression_invalid',
          'Target traffic percentage must be greater than or equal to initial',
          'targetTrafficPercentage',
          config.targetTrafficPercentage,
          `>= ${config.initialTrafficPercentage}`,
          ValidationCategory.SCHEMA
        )
      );
    }

    // Phases validation
    if (!config.phases || config.phases.length === 0) {
      errors.push(
        this.createError(
          'no_phases',
          'At least one deployment phase must be defined',
          'phases',
          config.phases,
          'array of phases',
          ValidationCategory.SCHEMA
        )
      );
    } else {
      this.validatePhases(config.phases, errors, warnings, context);
    }

    // Health check validation
    if (config.healthCheckIntervalMs < 10000) {
      warnings.push(
        this.createWarning(
          'frequent_health_checks',
          'Health check interval is very frequent, may impact performance',
          'healthCheckIntervalMs',
          config.healthCheckIntervalMs,
          '>= 10000',
          ValidationCategory.PERFORMANCE
        )
      );
    }

    // Timeout validation
    if (config.maxDeploymentTimeMs < 300000) {
      // 5 minutes
      warnings.push(
        this.createWarning(
          'short_deployment_timeout',
          'Maximum deployment time is very short, rollback may not complete',
          'maxDeploymentTimeMs',
          config.maxDeploymentTimeMs,
          '>= 300000',
          ValidationCategory.RELIABILITY
        )
      );
    }

    // Auto-rollback validation
    if (config.autoRollback && !config.rollbackThresholds) {
      errors.push(
        this.createError(
          'auto_rollback_no_thresholds',
          'Auto-rollback enabled but no rollback thresholds defined',
          'rollbackThresholds',
          config.rollbackThresholds,
          'rollback thresholds object',
          ValidationCategory.RELIABILITY
        )
      );
    }

    // Resource constraints validation
    if (context.resourceConstraints) {
      this.validateResourceConstraints(config as unknown as Record<string, unknown>, context.resourceConstraints, errors, warnings);
    }

    // Security validation
    this.validateCanaryDeploymentSecurity(config as unknown, context, errors, warnings);

    // Add best practice recommendations
    this.addCanaryDeploymentBestPractices(config as unknown as Record<string, unknown>, info);

    return this.createValidationResult(errors, warnings, info);
  }

  /**
   * Validate health monitor configuration
   */
  private validateHealthMonitorConfig(
    config: CanaryHealthConfig,
    context: ValidationContext
  ): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    const info: ValidationInfo[] = [];

    // Basic field validation
    this.validateRequiredFields(
      config,
      [
        'deploymentId',
        'serviceName',
        'stableVersion',
        'canaryVersion',
        'checkIntervalMs',
        'thresholds',
      ],
      errors,
      'health_monitor'
    );

    // Check interval validation
    if (config.checkIntervalMs < 30000) {
      warnings.push(
        this.createWarning(
          'frequent_health_checks',
          'Health check interval is very frequent, may impact performance',
          'checkIntervalMs',
          config.checkIntervalMs,
          '>= 30000',
          ValidationCategory.PERFORMANCE
        )
      );
    }

    // Thresholds validation
    if (!config.thresholds || (config.thresholds as any[]).length === 0) {
      errors.push(
        this.createError(
          'no_thresholds',
          'At least one health threshold must be defined',
          'thresholds',
          config.thresholds,
          'array of thresholds',
          ValidationCategory.MONITORING
        )
      );
    } else {
      this.validateHealthThresholds(config.thresholds, errors, warnings);
    }

    // Comparison settings validation
    if (config.comparisonEnabled && config.baselineWindow < 1) {
      errors.push(
        this.createError(
          'insufficient_baseline',
          'Baseline window must be at least 1 hour for meaningful comparison',
          'baselineWindow',
          config.baselineWindow,
          '>= 1',
          ValidationCategory.MONITORING
        )
      );
    }

    // Auto-rollback validation
    if (config.autoRollback.enabled && config.autoRollback.thresholds.length === 0) {
      errors.push(
        this.createError(
          'auto_rollback_no_thresholds',
          'Auto-rollback enabled but no rollback thresholds defined',
          'autoRollback.thresholds',
          config.autoRollback.thresholds,
          'array of rollback thresholds',
          ValidationCategory.RELIABILITY
        )
      );
    }

    // Add best practice recommendations
    this.addHealthMonitorBestPractices(config as unknown as Record<string, unknown>, info);

    return this.createValidationResult(errors, warnings, info);
  }

  /**
   * Validate rollback configuration
   */
  private validateRollbackConfig(
    config: RollbackConfig,
    context: ValidationContext
  ): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    const info: ValidationInfo[] = [];

    // Basic field validation
    this.validateRequiredFields(
      config,
      ['deploymentId', 'name', 'strategy', 'actions'],
      errors,
      'rollback'
    );

    // Strategy validation
    const validStrategies = ['immediate', 'gradual', 'phased', 'blue_green', 'custom'];
    if (!validStrategies.includes(config.strategy)) {
      errors.push(
        this.createError(
          'invalid_strategy',
          `Invalid rollback strategy. Must be one of: ${validStrategies.join(', ')}`,
          'strategy',
          config.strategy as string,
          validStrategies.join(', '),
          ValidationCategory.SCHEMA
        )
      );
    }

    // Actions validation
    if (!config.actions || config.actions.length === 0) {
      errors.push(
        this.createError(
          'no_actions',
          'At least one rollback action must be defined',
          'actions',
          config.actions,
          'array of actions',
          ValidationCategory.SCHEMA
        )
      );
    } else {
      this.validateRollbackActions(config.actions, errors, warnings);
    }

    // Phased rollback validation
    if (config.strategy === 'phased' && (!config.phases || config.phases.length === 0)) {
      errors.push(
        this.createError(
          'phased_no_phases',
          'Phased rollback strategy requires phases to be defined',
          'phases',
          config.phases,
          'array of phases',
          ValidationCategory.SCHEMA
        )
      );
    }

    // Safety controls validation
    if (
      config.safety.requireApproval &&
      (!config.safety.approvers || config.safety.approvers.length === 0)
    ) {
      errors.push(
        this.createError(
          'approval_no_approvers',
          'Approval required but no approvers defined',
          'safety.approvers',
          config.safety.approvers,
          'array of approvers',
          ValidationCategory.SECURITY
        )
      );
    }

    // Timeout validation
    if (config.safety.maxRollbackTimeMs < 60000) {
      // 1 minute
      warnings.push(
        this.createWarning(
          'short_rollback_timeout',
          'Maximum rollback time is very short, may not complete all actions',
          'safety.maxRollbackTimeMs',
          config.safety.maxRollbackTimeMs,
          '>= 60000',
          ValidationCategory.RELIABILITY
        )
      );
    }

    // Add best practice recommendations
    this.addRollbackBestPractices(config as unknown as Record<string, unknown>, info);

    return this.createValidationResult(errors, warnings, info);
  }

  /**
   * Validate traffic rule configuration
   */
  private validateTrafficRuleConfig(
    config: TrafficRule,
    context: ValidationContext
  ): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    const info: ValidationInfo[] = [];

    // Basic field validation
    this.validateRequiredFields(config, ['name', 'strategy', 'targets'], errors, 'traffic_rule');

    // Strategy validation
    const validStrategies = [
      'percentage',
      'round_robin',
      'weighted_round_robin',
      'least_connections',
      'consistent_hash',
    ];
    if (!validStrategies.includes(config.strategy)) {
      errors.push(
        this.createError(
          'invalid_strategy',
          `Invalid traffic strategy. Must be one of: ${validStrategies.join(', ')}`,
          'strategy',
          config.strategy as string,
          validStrategies.join(', '),
          ValidationCategory.SCHEMA
        )
      );
    }

    // Targets validation
    if (!config.targets || config.targets.length === 0) {
      errors.push(
        this.createError(
          'no_targets',
          'At least one target must be defined',
          'targets',
          config.targets,
          'array of targets',
          ValidationCategory.SCHEMA
        )
      );
    } else {
      this.validateTrafficTargets(config.targets, errors, warnings, context);
    }

    // Weight validation for percentage-based routing
    if (config.strategy === 'percentage') {
      const totalWeight = config.targets.reduce((sum, target) => sum + target.weight, 0);
      if (totalWeight !== 100) {
        errors.push(
          this.createError(
            'invalid_total_weight',
            'Total weight must equal 100 for percentage-based routing',
            'targets',
            totalWeight,
            100,
            ValidationCategory.SCHEMA
          )
        );
      }
    }

    // Health check validation
    if (config.healthCheck.enabled && config.healthCheck.intervalMs < 10000) {
      warnings.push(
        this.createWarning(
          'frequent_health_checks',
          'Health check interval is very frequent, may impact performance',
          'healthCheck.intervalMs',
          config.healthCheck.intervalMs,
          '>= 10000',
          ValidationCategory.PERFORMANCE
        )
      );
    }

    // Add best practice recommendations
    this.addTrafficRuleBestPractices(config as unknown as Record<string, unknown>, info);

    return this.createValidationResult(errors, warnings, info);
  }

  /**
   * Validate kill switch configuration
   */
  private validateKillSwitchConfig(
    config: KillSwitchConfig,
    context: ValidationContext
  ): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    const info: ValidationInfo[] = [];

    // Basic field validation
    this.validateRequiredFields(
      config,
      ['name', 'scope', 'triggerConditions'],
      errors,
      'kill_switch'
    );

    // Scope validation
    const validScopes = ['system_wide', 'component', 'feature', 'deployment', 'api_endpoint'];
    if (!validScopes.includes(config.scope)) {
      errors.push(
        this.createError(
          'invalid_scope',
          `Invalid scope. Must be one of: ${validScopes.join(', ')}`,
          'scope',
          config.scope,
          validScopes.join(', '),
          ValidationCategory.SCHEMA
        )
      );
    }

    // Target component validation for specific scopes
    if (
      (config.scope === 'component' || config.scope === 'api_endpoint') &&
      !config.targetComponent
    ) {
      errors.push(
        this.createError(
          'target_component_required',
          'Target component is required for this scope',
          'targetComponent',
          config.targetComponent,
          'component name',
          ValidationCategory.SCHEMA
        )
      );
    }

    // Trigger conditions validation
    if (!config.triggerConditions || (config.triggerConditions as any[]).length === 0) {
      errors.push(
        this.createError(
          'no_trigger_conditions',
          'At least one trigger condition must be defined',
          'triggerConditions',
          config.triggerConditions,
          'array of trigger conditions',
          ValidationCategory.SCHEMA
        )
      );
    }

    // Auto-recovery validation
    if (config.autoRecovery.enabled && config.autoRecovery.maxAttempts === 0) {
      warnings.push(
        this.createWarning(
          'auto_recovery_no_attempts',
          'Auto-recovery enabled but max attempts is 0',
          'autoRecovery.maxAttempts',
          config.autoRecovery.maxAttempts,
          '> 0',
          ValidationCategory.RELIABILITY
        )
      );
    }

    // Add best practice recommendations
    this.addKillSwitchBestPractices(config as unknown as Record<string, unknown>, info);

    return this.createValidationResult(errors, warnings, info);
  }

  /**
   * Validate feature flag configuration
   */
  private validateFeatureFlagConfig(
    config: FeatureFlag,
    context: ValidationContext
  ): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    const info: ValidationInfo[] = [];

    // Basic field validation
    this.validateRequiredFields(config, ['name', 'status', 'strategy'], errors, 'feature_flag');

    // Strategy validation
    const validStrategies = [
      'all_users',
      'percentage',
      'cohort',
      'user_list',
      'attribute_based',
      'ab_test',
    ];
    if (!validStrategies.includes(config.strategy)) {
      errors.push(
        this.createError(
          'invalid_strategy',
          `Invalid strategy. Must be one of: ${validStrategies.join(', ')}`,
          'strategy',
          config.strategy as string,
          validStrategies.join(', '),
          ValidationCategory.SCHEMA
        )
      );
    }

    // Percentage strategy validation
    if (
      config.strategy === 'percentage' &&
      (config.rolloutPercentage === undefined ||
        config.rolloutPercentage < 0 ||
        config.rolloutPercentage > 100)
    ) {
      errors.push(
        this.createError(
          'invalid_percentage',
          'Rollout percentage must be between 0 and 100 for percentage strategy',
          'rolloutPercentage',
          config.rolloutPercentage,
          '0-100',
          ValidationCategory.SCHEMA
        )
      );
    }

    // Cohort strategy validation
    if (
      config.strategy === 'cohort' &&
      (!config.targetCohorts || config.targetCohorts.length === 0)
    ) {
      errors.push(
        this.createError(
          'cohort_no_targets',
          'Target cohorts must be specified for cohort strategy',
          'targetCohorts',
          config.targetCohorts,
          'array of cohort IDs',
          ValidationCategory.SCHEMA
        )
      );
    }

    // User list strategy validation
    if (
      config.strategy === 'user_list' &&
      (!config.targetUsers || config.targetUsers.length === 0)
    ) {
      errors.push(
        this.createError(
          'user_list_no_targets',
          'Target users must be specified for user list strategy',
          'targetUsers',
          config.targetUsers,
          'array of user IDs',
          ValidationCategory.SCHEMA
        )
      );
    }

    // A/B test validation
    if (config.strategy === 'ab_test' && !config.abTestConfig) {
      errors.push(
        this.createError(
          'ab_test_no_config',
          'A/B test configuration must be specified for ab_test strategy',
          'abTestConfig',
          config.abTestConfig,
          'A/B test configuration',
          ValidationCategory.SCHEMA
        )
      );
    }

    // Kill switch validation
    if (config.killSwitchEnabled && !config.emergencyDisabled) {
      info.push(
        this.createInfo(
          'kill_switch_enabled',
          'Kill switch is enabled for this feature flag',
          'killSwitchEnabled',
          config.killSwitchEnabled,
          ValidationCategory.SECURITY,
          true
        )
      );
    }

    // Add best practice recommendations
    this.addFeatureFlagBestPractices(config as unknown as Record<string, unknown>, info);

    return this.createValidationResult(errors, warnings, info);
  }

  // ============================================================================
  // Specialized Validation Methods
  // ============================================================================

  /**
   * Validate deployment phases
   */
  private validatePhases(
    phases: DeploymentPhase[],
    errors: ValidationError[],
    warnings: ValidationWarning[],
    context: ValidationContext
  ): void {
    // Check for phase order (using array index as order)
    for (let i = 0; i < phases.length; i++) {
      const phase = phases[i];
      if (phase && phase.id && typeof phase.id === 'string') {
        // Validate that phase IDs are unique
        const duplicateCount = phases.filter((p) => p.id === phase.id).length;
        if (duplicateCount > 1) {
          errors.push(
            this.createError(
              'duplicate_phase_id',
              'Phase IDs must be unique',
              `phases[${i}].id`,
              phase.id,
              'unique identifier',
              ValidationCategory.SCHEMA
            )
          );
        }
      }
    }

    // Check phase durations
    for (const phase of phases) {
      if (phase.durationMs < 60000) {
        // 1 minute
        warnings.push(
          this.createWarning(
            'short_phase_duration',
            'Phase duration is very short, may not provide sufficient time for evaluation',
            `phases[${phase.id}].durationMs`,
            phase.durationMs,
            '>= 60000',
            ValidationCategory.PERFORMANCE
          )
        );
      }
    }

    // Check traffic progression
    for (let i = 1; i < phases.length; i++) {
      const prevPhase = phases[i - 1];
      const currPhase = phases[i];

      if (currPhase.trafficPercentage < prevPhase.trafficPercentage) {
        warnings.push(
          this.createWarning(
            'traffic_not_monotonic',
            'Traffic percentage should generally increase across phases',
            `phases[${currPhase.id}].trafficPercentage`,
            currPhase.trafficPercentage,
            `>= ${prevPhase.trafficPercentage}`,
            ValidationCategory.BEST_PRACTICE
          )
        );
      }
    }
  }

  /**
   * Validate health thresholds
   */
  private validateHealthThresholds(
    thresholds: HealthThreshold[],
    errors: ValidationError[],
    warnings: ValidationWarning[]
  ): void {
    for (const threshold of thresholds) {
      if (threshold.warning >= threshold.critical) {
        errors.push(
          this.createError(
            'threshold_values_invalid',
            'Warning threshold must be less than critical threshold',
            'thresholds.warning',
            threshold.warning,
            `< critical threshold`,
            ValidationCategory.SCHEMA
          )
        );
      }

      if (threshold.windowSize < 1) {
        errors.push(
          this.createError(
            'threshold_window_invalid',
            'Window size must be at least 1 minute',
            'thresholds.windowSize',
            threshold.windowSize,
            '>= 1',
            ValidationCategory.SCHEMA
          )
        );
      }
    }
  }

  /**
   * Validate rollback actions
   */
  private validateRollbackActions(
    actions: ActionConfig[],
    errors: ValidationError[],
    warnings: ValidationWarning[]
  ): void {
    const validActionTypes = [
      'stop_new_traffic',
      'drain_connections',
      'update_feature_flags',
      'disable_kill_switches',
      'route_traffic',
      'scale_down',
      'scale_up',
      'restart_services',
      'clear_caches',
      'update_config',
      'run_validation',
      'notify_users',
      'custom',
    ];

    for (const action of actions) {
      if (!validActionTypes.includes(action.type)) {
        errors.push(
          this.createError(
            'invalid_action_type',
            `Invalid action type. Must be one of: ${validActionTypes.join(', ')}`,
            'actions.type',
            action.type,
            validActionTypes.join(', '),
            ValidationCategory.SCHEMA
          )
        );
      }

      if (action.timeoutMs < 5000) {
        warnings.push(
          this.createWarning(
            'short_action_timeout',
            'Action timeout is very short, may not complete successfully',
            'actions.timeoutMs',
            action.timeoutMs,
            '>= 5000',
            ValidationCategory.RELIABILITY
          )
        );
      }
    }
  }

  /**
   * Validate traffic targets
   */
  private validateTrafficTargets(
    targets: TargetConfig[],
    errors: ValidationError[],
    warnings: ValidationWarning[],
    context: ValidationContext
  ): void {
    for (const target of targets) {
      if (!target.endpoint) {
        errors.push(
          this.createError(
            'target_no_endpoint',
            'Target must have an endpoint',
            'targets.endpoint',
            target.endpoint,
            'endpoint URL',
            ValidationCategory.SCHEMA
          )
        );
      }

      if (target.weight < 0 || target.weight > 100) {
        errors.push(
          this.createError(
            'invalid_target_weight',
            'Target weight must be between 0 and 100',
            'targets.weight',
            target.weight,
            '0-100',
            ValidationCategory.SCHEMA
          )
        );
      }

      if (!target.name) {
        warnings.push(
          this.createWarning(
            'target_no_name',
            'Target should have a descriptive name',
            'targets.name',
            target.name,
            'descriptive name',
            ValidationCategory.BEST_PRACTICE
          )
        );
      }
    }
  }

  /**
   * Validate resource constraints
   */
  private validateResourceConstraints(
    config: Record<string, unknown>,
    constraints: ResourceConstraints,
    errors: ValidationError[],
    warnings: ValidationWarning[]
  ): void {
    if (
      constraints.maxTrafficPercentage &&
      typeof config.targetTrafficPercentage === 'number' &&
      config.targetTrafficPercentage > constraints.maxTrafficPercentage
    ) {
      errors.push(
        this.createError(
          'traffic_exceeds_constraint',
          'Target traffic percentage exceeds resource constraints',
          'targetTrafficPercentage',
          config.targetTrafficPercentage,
          `<= ${constraints.maxTrafficPercentage}`,
          ValidationCategory.RESOURCE
        )
      );
    }

    if (
      constraints.maxRollbackTime &&
      typeof config.maxDeploymentTimeMs === 'number' &&
      config.maxDeploymentTimeMs > constraints.maxRollbackTime
    ) {
      warnings.push(
        this.createWarning(
          'deployment_exceeds_rollback_time',
          'Maximum deployment time exceeds rollback time constraint',
          'maxDeploymentTimeMs',
          config.maxDeploymentTimeMs,
          `<= ${constraints.maxRollbackTime}`,
          ValidationCategory.RESOURCE
        )
      );
    }
  }

  /**
   * Validate canary deployment security
   */
  private validateCanaryDeploymentSecurity(
    config: unknown,
    context: ValidationContext,
    errors: ValidationError[],
    warnings: ValidationWarning[]
  ): void {
    if (context.securityPolicies) {
      for (const policy of context.securityPolicies) {
        for (const rule of policy.rules) {
          if (rule.required) {
            // Check if security requirements are met
            this.validateSecurityRule(rule, config, errors, warnings);
          }
        }
      }
    }

    // Check for sensitive data in configuration
    if (this.containsSensitiveData(config)) {
      errors.push(
        this.createError(
          'sensitive_data_exposed',
          'Configuration contains sensitive data that should be secured',
          'config',
          'contains sensitive data',
          'remove or encrypt sensitive data',
          ValidationCategory.SECURITY
        )
      );
    }
  }

  /**
   * Validate security rule
   */
  private validateSecurityRule(
    rule: SecurityRule,
    config: unknown,
    errors: ValidationError[],
    warnings: ValidationWarning[]
  ): void {
    // Implementation would depend on specific security rules
    // For now, just log that we're checking security
    logger.debug('Checking security rule', { type: rule.type, required: rule.required });
  }

  // ============================================================================
  // Best Practice Recommendations
  // ============================================================================

  /**
   * Add canary deployment best practices
   */
  private addCanaryDeploymentBestPractices(
    config: Record<string, unknown>,
    info: ValidationInfo[]
  ): void {
    if ((config.initialTrafficPercentage as number) > 10) {
      info.push(
        this.createInfo(
          'conservative_initial_traffic',
          'Consider starting with lower initial traffic percentage (1-5%) for safer rollouts',
          'initialTrafficPercentage',
          config.initialTrafficPercentage as number,
          ValidationCategory.BEST_PRACTICE,
          true,
          'https://example.com/canary-best-practices'
        )
      );
    }

    if ((config.phases as any[]).length < 3) {
      info.push(
        this.createInfo(
          'more_phases_recommended',
          'Consider using more phases for gradual traffic increase and better monitoring',
          'phases.length',
          (config.phases as any[]).length,
          ValidationCategory.BEST_PRACTICE,
          true
        )
      );
    }

    if (!config.autoRollback) {
      info.push(
        this.createInfo(
          'auto_rollback_recommended',
          'Consider enabling auto-rollback for automatic failure recovery',
          'autoRollback',
          config.autoRollback as any,
          ValidationCategory.BEST_PRACTICE,
          true
        )
      );
    }
  }

  /**
   * Add health monitor best practices
   */
  private addHealthMonitorBestPractices(
    config: Record<string, unknown>,
    info: ValidationInfo[]
  ): void {
    if (!config.comparisonEnabled) {
      info.push(
        this.createInfo(
          'comparison_recommended',
          'Consider enabling comparison for better canary vs stable analysis',
          'comparisonEnabled',
          config.comparisonEnabled,
          ValidationCategory.BEST_PRACTICE,
          true
        )
      );
    }

    if ((config.thresholds as any[]).length < 3) {
      info.push(
        this.createInfo(
          'more_thresholds_recommended',
          'Consider defining more health thresholds for comprehensive monitoring',
          'thresholds.length',
          (config.thresholds as any[]).length,
          ValidationCategory.BEST_PRACTICE,
          true
        )
      );
    }
  }

  /**
   * Add rollback best practices
   */
  private addRollbackBestPractices(config: Record<string, unknown>, info: ValidationInfo[]): void {
    if (!(config.safety as any).requireApproval) {
      info.push(
        this.createInfo(
          'approval_recommended',
          'Consider requiring approval for rollback operations in production',
          'safety.requireApproval',
          (config.safety as any).requireApproval,
          ValidationCategory.BEST_PRACTICE,
          true
        )
      );
    }

    if (config.strategy === 'immediate') {
      info.push(
        this.createInfo(
          'gradual_rollback_recommended',
          'Consider using gradual or phased rollback for smoother transitions',
          'strategy',
          config.strategy as string,
          ValidationCategory.BEST_PRACTICE,
          true
        )
      );
    }
  }

  /**
   * Add traffic rule best practices
   */
  private addTrafficRuleBestPractices(
    config: Record<string, unknown>,
    info: ValidationInfo[]
  ): void {
    if (!(config.sessionAffinity as any).enabled) {
      info.push(
        this.createInfo(
          'session_affinity_recommended',
          'Consider enabling session affinity for consistent user experience',
          'sessionAffinity.enabled',
          (config.sessionAffinity as any).enabled,
          ValidationCategory.BEST_PRACTICE,
          true
        )
      );
    }

    if (!(config.failover as any).enabled) {
      info.push(
        this.createInfo(
          'failover_recommended',
          'Consider enabling failover for better reliability',
          'failover.enabled',
          (config.failover as any).enabled,
          ValidationCategory.BEST_PRACTICE,
          true
        )
      );
    }
  }

  /**
   * Add kill switch best practices
   */
  private addKillSwitchBestPractices(
    config: Record<string, unknown>,
    info: ValidationInfo[]
  ): void {
    if (!(config.autoRecovery as any).enabled) {
      info.push(
        this.createInfo(
          'auto_recovery_recommended',
          'Consider enabling auto-recovery for automatic issue resolution',
          'autoRecovery.enabled',
          (config.autoRecovery as any).enabled,
          ValidationCategory.BEST_PRACTICE,
          true
        )
      );
    }

    if ((config.triggerConditions as any[]).length < 2) {
      info.push(
        this.createInfo(
          'more_triggers_recommended',
          'Consider defining multiple trigger conditions for comprehensive monitoring',
          'triggerConditions.length',
          (config.triggerConditions as any[]).length,
          ValidationCategory.BEST_PRACTICE,
          true
        )
      );
    }
  }

  /**
   * Add feature flag best practices
   */
  private addFeatureFlagBestPractices(
    config: Record<string, unknown>,
    info: ValidationInfo[]
  ): void {
    if (!config.description) {
      info.push(
        this.createInfo(
          'description_recommended',
          'Consider adding a description for better flag documentation',
          'description',
          config.description,
          ValidationCategory.BEST_PRACTICE,
          true
        )
      );
    }

    if (!config.expiredAt && config.status === 'enabled') {
      info.push(
        this.createInfo(
          'expiration_recommended',
          'Consider setting an expiration date for temporary flags',
          'expiredAt',
          config.expiredAt,
          ValidationCategory.BEST_PRACTICE,
          true
        )
      );
    }
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  /**
   * Validate required fields
   */
  private validateRequiredFields(
    config: unknown,
    requiredFields: string[],
    errors: ValidationError[],
    configType: string
  ): void {
    if (typeof config !== 'object' || config === null) {
      errors.push(
        this.createError(
          'invalid_config_type',
          'Configuration must be an object',
          'config',
          config,
          'object',
          ValidationCategory.SCHEMA
        )
      );
      return;
    }

    for (const field of requiredFields) {
      if (
        !(field in config) ||
        (config as unknown as Record<string, unknown>)[field] === undefined ||
        (config as unknown as Record<string, unknown>)[field] === null ||
        (config as unknown as Record<string, unknown>)[field] === ''
      ) {
        errors.push(
          this.createError(
            'required_field_missing',
            `Required field '${field}' is missing or empty`,
            field,
            (config as unknown as Record<string, unknown>)[field],
            'required value',
            ValidationCategory.SCHEMA
          )
        );
      }
    }
  }

  /**
   * Check for sensitive data
   */
  private containsSensitiveData(config: unknown): boolean {
    const sensitivePatterns = [/password/i, /secret/i, /key/i, /token/i, /credential/i];

    const configString = JSON.stringify(config);
    return sensitivePatterns.some((pattern) => pattern.test(configString));
  }

  /**
   * Apply strict mode validation
   */
  private applyStrictMode(result: ValidationResult): ValidationResult {
    // In strict mode, treat warnings as errors
    const warningsAsErrors = result.warnings.map(
      (warning) =>
        ({
          ...warning,
          severity: ValidationSeverity.ERROR as ValidationSeverity,
          category: ValidationCategory.BEST_PRACTICE,
          fixable: warning.actionable,
        }) as ValidationError
    );

    result.errors.push(...warningsAsErrors);
    result.warnings = [];

    // Update validity
    result.valid = result.errors.length === 0;
    result.summary.errorIssues += warningsAsErrors.length;
    result.summary.warningIssues = 0;
    result.summary.totalIssues = result.errors.length + result.info.length;

    return result;
  }

  /**
   * Create validation error
   */
  private createError(
    code: string,
    message: string,
    field?: string,
    value?: unknown,
    expectedValue?: unknown,
    category: ValidationCategory = ValidationCategory.SCHEMA
  ): ValidationError {
    return {
      id: this.generateId(),
      code,
      message,
      field,
      value,
      expectedValue,
      severity: ValidationSeverity.ERROR,
      category,
      fixable: true,
      fixSuggestion: expectedValue ? `Should be ${expectedValue}` : undefined,
    };
  }

  /**
   * Create validation warning
   */
  private createWarning(
    code: string,
    message: string,
    field?: string,
    value?: unknown,
    recommendedValue?: unknown,
    category: ValidationCategory = ValidationCategory.BEST_PRACTICE
  ): ValidationWarning {
    return {
      id: this.generateId(),
      code,
      message,
      field,
      value,
      recommendedValue,
      severity: ValidationSeverity.WARNING,
      category,
      actionable: true,
      actionSuggestion: recommendedValue ? `Consider using ${recommendedValue}` : undefined,
    };
  }

  /**
   * Create validation info
   */
  private createInfo(
    code: string,
    message: string,
    field?: string,
    value?: unknown,
    category: ValidationCategory = ValidationCategory.BEST_PRACTICE,
    bestPractice: boolean = true,
    reference?: string
  ): ValidationInfo {
    return {
      id: this.generateId(),
      code,
      message,
      field,
      value,
      severity: ValidationSeverity.INFO,
      category,
      bestPractice,
      reference,
    };
  }

  /**
   * Create validation result
   */
  private createValidationResult(
    errors: ValidationError[],
    warnings: ValidationWarning[],
    info: ValidationInfo[]
  ): ValidationResult {
    const summary = {
      totalIssues: errors.length + warnings.length + info.length,
      criticalIssues: errors.filter((e) => e.severity === ValidationSeverity.CRITICAL).length,
      errorIssues: errors.filter((e) => e.severity === ValidationSeverity.ERROR).length,
      warningIssues: warnings.length,
      infoIssues: info.length,
    };

    const recommendations = [
      ...errors
        .filter((e) => e.fixable)
        .map((e) => e.fixSuggestion || 'Fix the configuration error'),
      ...warnings
        .filter((w) => w.actionable)
        .map((w) => w.actionSuggestion || 'Address the configuration warning'),
      ...info.filter((i) => i.bestPractice).map((i) => `Consider best practice: ${i.message}`),
    ];

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      info,
      summary,
      recommendations,
      validatedAt: new Date(),
    };
  }

  /**
   * Create error result
   */
  private createErrorResult(message: string): ValidationResult {
    const error: ValidationError = {
      id: this.generateId(),
      code: 'validation_error',
      message,
      severity: ValidationSeverity.CRITICAL,
      category: ValidationCategory.SCHEMA,
      fixable: false,
    };

    return {
      valid: false,
      errors: [error],
      warnings: [],
      info: [],
      summary: {
        totalIssues: 1,
        criticalIssues: 1,
        errorIssues: 0,
        warningIssues: 0,
        infoIssues: 0,
      },
      recommendations: ['Fix the validation error'],
      validatedAt: new Date(),
    };
  }

  /**
   * Generate unique ID
   */
  private generateId(): string {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
  }

  /**
   * Initialize validation rules
   */
  private initializeValidationRules(): void {
    // Initialize validation rules for different configuration types
    this.validationRules.set('canary_deployment', []);
    this.validationRules.set('health_monitor', []);
    this.validationRules.set('rollback', []);
    this.validationRules.set('traffic_rule', []);
    this.validationRules.set('kill_switch', []);
    this.validationRules.set('feature_flag', []);
  }

  /**
   * Initialize schemas
   */
  private initializeSchemas(): void {
    // Initialize JSON schemas for different configuration types
    // This would contain actual JSON schema definitions
  }

  /**
   * Get validation statistics
   */
  getStatistics(): {
    totalValidations: number;
    successfulValidations: number;
    failedValidations: number;
    commonErrors: Record<string, number>;
    commonWarnings: Record<string, number>;
  } {
    // Return validation statistics
    return {
      totalValidations: 0,
      successfulValidations: 0,
      failedValidations: 0,
      commonErrors: {},
      commonWarnings: {},
    };
  }
}

// Export singleton instance
export const canaryConfigValidator = new CanaryConfigValidator();
