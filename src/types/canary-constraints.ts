/**
 * Compile-Time Constraint Validation for Canary Configurations
 *
 * Provides type-safe constraint validation with compile-time checks for:
 * - Traffic percentage constraints
 * - Phase sequencing validation
 * - Health threshold bounds checking
 * - Configuration dependency verification
 * - Resource allocation limits
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import {
  type CanaryPhaseId,
  createCanaryPhaseId,
  createDeploymentId,
  createThresholdValue,
  createTrafficPercentage,
  type DeploymentId,
  isValidCanaryPhaseId,
  isValidDeploymentId,
  isValidThresholdValue,
  isValidTrafficPercentage,
  type ThresholdValue,
  type TrafficPercentage,
} from './branded-types.js';

// ============================================================================
// Constraint Validation Types
// ============================================================================

/**
 * Constraint validation result
 */
export interface ConstraintValidationResult<T = unknown> {
  isValid: boolean;
  value: T;
  errors: ValidationError[];
  warnings: ValidationWarning[];
}

/**
 * Validation error
 */
export interface ValidationError {
  field: string;
  message: string;
  code: string;
  severity: 'error';
}

/**
 * Validation warning
 */
export interface ValidationWarning {
  field: string;
  message: string;
  code: string;
  severity: 'warning';
}

/**
 * Constraint violation type
 */
export enum ConstraintType {
  TRAFFIC_PERCENTAGE = 'traffic_percentage',
  PHASE_SEQUENCE = 'phase_sequence',
  THRESHOLD_BOUNDS = 'threshold_bounds',
  RESOURCE_LIMITS = 'resource_limits',
  TIME_WINDOW = 'time_window',
  DEPENDENCY = 'dependency',
  NAMING_CONVENTION = 'naming_convention',
  VERSION_FORMAT = 'version_format',
}

// ============================================================================
// Traffic Percentage Constraints
// ============================================================================

/**
 * Traffic percentage constraints
 */
export interface TrafficPercentageConstraints {
  minimumInitial: number;
  maximumInitial: number;
  maximumPhaseIncrease: number;
  maximumTotal: number;
  requireProgression: boolean;
}

/**
 * Default traffic percentage constraints
 */
export const DEFAULT_TRAFFIC_CONSTRAINTS: TrafficPercentageConstraints = {
  minimumInitial: 1,
  maximumInitial: 10,
  maximumPhaseIncrease: 50,
  maximumTotal: 100,
  requireProgression: true,
} as const;

/**
 * Validate initial traffic percentage
 */
export function validateInitialTrafficPercentage(
  percentage: number,
  constraints: TrafficPercentageConstraints = DEFAULT_TRAFFIC_CONSTRAINTS
): ConstraintValidationResult<TrafficPercentage> {
  const errors: ValidationError[] = [];
  const warnings: ValidationWarning[] = [];

  if (!isValidTrafficPercentage(percentage)) {
    errors.push({
      field: 'initialTrafficPercentage',
      message: `Invalid traffic percentage: ${percentage}`,
      code: 'INVALID_TRAFFIC_PERCENTAGE',
      severity: 'error',
    });
  }

  if (percentage < constraints.minimumInitial) {
    errors.push({
      field: 'initialTrafficPercentage',
      message: `Initial traffic percentage ${percentage}% is below minimum ${constraints.minimumInitial}%`,
      code: 'INITIAL_TRAFFIC_TOO_LOW',
      severity: 'error',
    });
  }

  if (percentage > constraints.maximumInitial) {
    warnings.push({
      field: 'initialTrafficPercentage',
      message: `Initial traffic percentage ${percentage}% is above recommended maximum ${constraints.maximumInitial}%`,
      code: 'INITIAL_TRAFFIC_TOO_HIGH',
      severity: 'warning',
    });
  }

  return {
    isValid: errors.length === 0,
    value: createTrafficPercentage(percentage),
    errors,
    warnings,
  };
}

/**
 * Validate phase traffic progression
 */
export function validatePhaseProgression(
  phases: Array<{ id: string; trafficPercentage: number }>,
  constraints: TrafficPercentageConstraints = DEFAULT_TRAFFIC_CONSTRAINTS
): ConstraintValidationResult<Array<{ id: CanaryPhaseId; trafficPercentage: TrafficPercentage }>> {
  const errors: ValidationError[] = [];
  const warnings: ValidationWarning[] = [];

  const validatedPhases: Array<{ id: CanaryPhaseId; trafficPercentage: TrafficPercentage }> = [];

  // Validate each phase
  for (let i = 0; i < phases.length; i++) {
    const phase = phases[i];
    const phaseErrors: ValidationError[] = [];
    const phaseWarnings: ValidationWarning[] = [];

    // Validate phase ID
    if (!isValidCanaryPhaseId(phase.id)) {
      phaseErrors.push({
        field: `phases[${i}].id`,
        message: `Invalid phase ID: ${phase.id}`,
        code: 'INVALID_PHASE_ID',
        severity: 'error',
      });
    }

    // Validate traffic percentage
    if (!isValidTrafficPercentage(phase.trafficPercentage)) {
      phaseErrors.push({
        field: `phases[${i}].trafficPercentage`,
        message: `Invalid traffic percentage: ${phase.trafficPercentage}`,
        code: 'INVALID_TRAFFIC_PERCENTAGE',
        severity: 'error',
      });
    }

    // Check progression
    if (constraints.requireProgression && i > 0) {
      const prevPhase = phases[i - 1];
      if (phase.trafficPercentage < prevPhase.trafficPercentage) {
        errors.push({
          field: `phases[${i}].trafficPercentage`,
          message: `Phase ${i} traffic percentage (${phase.trafficPercentage}%) is less than previous phase (${prevPhase.trafficPercentage}%)`,
          code: 'TRAFFIC_REGRESSION',
          severity: 'error',
        });
      }

      const increase = phase.trafficPercentage - prevPhase.trafficPercentage;
      if (increase > constraints.maximumPhaseIncrease) {
        warnings.push({
          field: `phases[${i}].trafficPercentage`,
          message: `Traffic increase ${increase}% from previous phase exceeds recommended maximum ${constraints.maximumPhaseIncrease}%`,
          code: 'TRAFFIC_INCREASE_TOO_HIGH',
          severity: 'warning',
        });
      }
    }

    // Check total limit
    if (phase.trafficPercentage > constraints.maximumTotal) {
      errors.push({
        field: `phases[${i}].trafficPercentage`,
        message: `Phase traffic percentage ${phase.trafficPercentage}% exceeds maximum ${constraints.maximumTotal}%`,
        code: 'TRAFFIC_EXCEEDS_MAXIMUM',
        severity: 'error',
      });
    }

    errors.push(...phaseErrors);
    warnings.push(...phaseWarnings);

    if (phaseErrors.length === 0) {
      validatedPhases.push({
        id: createCanaryPhaseId(phase.id),
        trafficPercentage: createTrafficPercentage(phase.trafficPercentage),
      });
    }
  }

  return {
    isValid: errors.length === 0,
    value: validatedPhases,
    errors,
    warnings,
  };
}

// ============================================================================
// Health Threshold Constraints
// ============================================================================

/**
 * Health threshold constraints
 */
export interface HealthThresholdConstraints {
  minimumWarningWindow: number;
  maximumWarningWindow: number;
  minimumCriticalWindow: number;
  maximumCriticalWindow: number;
  requireWarningBelowCritical: boolean;
  maximumThresholdValue: number;
}

/**
 * Default health threshold constraints
 */
export const DEFAULT_HEALTH_THRESHOLD_CONSTRAINTS: HealthThresholdConstraints = {
  minimumWarningWindow: 1,
  maximumWarningWindow: 60,
  minimumCriticalWindow: 1,
  maximumCriticalWindow: 60,
  requireWarningBelowCritical: boolean,
  maximumThresholdValue: 1000000,
} as const;

/**
 * Validate health threshold
 */
export function validateHealthThreshold(
  threshold: {
    metric: string;
    warning: number;
    critical: number;
    windowSize: number;
    operator: 'less_than' | 'greater_than' | 'equals';
  },
  constraints: HealthThresholdConstraints = DEFAULT_HEALTH_THRESHOLD_CONSTRAINTS
): ConstraintValidationResult<{
  metric: string;
  warning: ThresholdValue;
  critical: ThresholdValue;
  windowSize: number;
  operator: 'less_than' | 'greater_than' | 'equals';
}> {
  const errors: ValidationError[] = [];
  const warnings: ValidationWarning[] = [];

  // Validate warning threshold
  if (!isValidThresholdValue(threshold.warning)) {
    errors.push({
      field: 'threshold.warning',
      message: `Invalid warning threshold: ${threshold.warning}`,
      code: 'INVALID_WARNING_THRESHOLD',
      severity: 'error',
    });
  }

  if (threshold.warning > constraints.maximumThresholdValue) {
    errors.push({
      field: 'threshold.warning',
      message: `Warning threshold ${threshold.warning} exceeds maximum ${constraints.maximumThresholdValue}`,
      code: 'WARNING_THRESHOLD_TOO_HIGH',
      severity: 'error',
    });
  }

  // Validate critical threshold
  if (!isValidThresholdValue(threshold.critical)) {
    errors.push({
      field: 'threshold.critical',
      message: `Invalid critical threshold: ${threshold.critical}`,
      code: 'INVALID_CRITICAL_THRESHOLD',
      severity: 'error',
    });
  }

  if (threshold.critical > constraints.maximumThresholdValue) {
    errors.push({
      field: 'threshold.critical',
      message: `Critical threshold ${threshold.critical} exceeds maximum ${constraints.maximumThresholdValue}`,
      code: 'CRITICAL_THRESHOLD_TOO_HIGH',
      severity: 'error',
    });
  }

  // Validate window size
  if (threshold.windowSize < constraints.minimumWarningWindow || threshold.windowSize > constraints.maximumWarningWindow) {
    errors.push({
      field: 'threshold.windowSize',
      message: `Window size ${threshold.windowSize} must be between ${constraints.minimumWarningWindow} and ${constraints.maximumWarningWindow}`,
      code: 'INVALID_WINDOW_SIZE',
      severity: 'error',
    });
  }

  // Validate warning vs critical relationship
  if (constraints.requireWarningBelowCritical) {
    if (threshold.warning >= threshold.critical) {
      errors.push({
        field: 'threshold.warning',
        message: `Warning threshold ${threshold.warning} must be less than critical threshold ${threshold.critical}`,
        code: 'WARNING_ABOVE_CRITICAL',
        severity: 'error',
      });
    }
  }

  return {
    isValid: errors.length === 0,
    value: {
      metric: threshold.metric,
      warning: createThresholdValue(threshold.warning),
      critical: createThresholdValue(threshold.critical),
      windowSize: threshold.windowSize,
      operator: threshold.operator,
    },
    errors,
    warnings,
  };
}

// ============================================================================
// Deployment Configuration Constraints
// ============================================================================

/**
 * Deployment configuration constraints
 */
export interface DeploymentConfigConstraints {
  minimumDeploymentTime: number;
  maximumDeploymentTime: number;
  minimumHealthCheckInterval: number;
  maximumHealthCheckInterval: number;
  minimumRetentionHours: number;
  maximumRetentionHours: number;
  requiredPhases: {
    min: number;
    max: number;
  };
}

/**
 * Default deployment configuration constraints
 */
export const DEFAULT_DEPLOYMENT_CONSTRAINTS: DeploymentConfigConstraints = {
  minimumDeploymentTime: 60000, // 1 minute
  maximumDeploymentTime: 86400000, // 24 hours
  minimumHealthCheckInterval: 10000, // 10 seconds
  maximumHealthCheckInterval: 300000, // 5 minutes
  minimumRetentionHours: 1,
  maximumRetentionHours: 168, // 1 week
  requiredPhases: {
    min: 1,
    max: 10,
  },
} as const;

/**
 * Validate deployment configuration
 */
export function validateDeploymentConfig(
  config: {
    deploymentId: string;
    serviceName: string;
    stableVersion: string;
    canaryVersion: string;
    maxDeploymentTimeMs: number;
    healthCheckIntervalMs: number;
    metricsRetentionHours: number;
    phases: Array<{ id: string; trafficPercentage: number; durationMs: number }>;
  },
  constraints: DeploymentConfigConstraints = DEFAULT_DEPLOYMENT_CONSTRAINTS
): ConstraintValidationResult<{
  deploymentId: DeploymentId;
  serviceName: string;
  stableVersion: string;
  canaryVersion: string;
  maxDeploymentTimeMs: number;
  healthCheckIntervalMs: number;
  metricsRetentionHours: number;
  phases: Array<{ id: CanaryPhaseId; trafficPercentage: TrafficPercentage; durationMs: number }>;
}> {
  const errors: ValidationError[] = [];
  const warnings: ValidationWarning[] = [];

  // Validate deployment ID
  if (!isValidDeploymentId(config.deploymentId)) {
    errors.push({
      field: 'deploymentId',
      message: `Invalid deployment ID: ${config.deploymentId}`,
      code: 'INVALID_DEPLOYMENT_ID',
      severity: 'error',
    });
  }

  // Validate deployment time
  if (config.maxDeploymentTimeMs < constraints.minimumDeploymentTime) {
    errors.push({
      field: 'maxDeploymentTimeMs',
      message: `Deployment time ${config.maxDeploymentTimeMs}ms is below minimum ${constraints.minimumDeploymentTimeMs}ms`,
      code: 'DEPLOYMENT_TIME_TOO_SHORT',
      severity: 'error',
    });
  }

  if (config.maxDeploymentTimeMs > constraints.maximumDeploymentTime) {
    warnings.push({
      field: 'maxDeploymentTimeMs',
      message: `Deployment time ${config.maxDeploymentTimeMs}ms exceeds recommended maximum ${constraints.maximumDeploymentTimeMs}ms`,
      code: 'DEPLOYMENT_TIME_TOO_LONG',
      severity: 'warning',
    });
  }

  // Validate health check interval
  if (config.healthCheckIntervalMs < constraints.minimumHealthCheckInterval) {
    errors.push({
      field: 'healthCheckIntervalMs',
      message: `Health check interval ${config.healthCheckIntervalMs}ms is below minimum ${constraints.minimumHealthCheckIntervalMs}ms`,
      code: 'HEALTH_CHECK_INTERVAL_TOO_SHORT',
      severity: 'error',
    });
  }

  if (config.healthCheckIntervalMs > constraints.maximumHealthCheckInterval) {
    warnings.push({
      field: 'healthCheckIntervalMs',
      message: `Health check interval ${config.healthCheckIntervalMs}ms exceeds recommended maximum ${constraints.maximumHealthCheckIntervalMs}ms`,
      code: 'HEALTH_CHECK_INTERVAL_TOO_LONG',
      severity: 'warning',
    });
  }

  // Validate retention hours
  if (config.metricsRetentionHours < constraints.minimumRetentionHours) {
    errors.push({
      field: 'metricsRetentionHours',
      message: `Retention hours ${config.metricsRetentionHours} is below minimum ${constraints.minimumRetentionHours}`,
      code: 'RETENTION_TOO_SHORT',
      severity: 'error',
    });
  }

  if (config.metricsRetentionHours > constraints.maximumRetentionHours) {
    warnings.push({
      field: 'metricsRetentionHours',
      message: `Retention hours ${config.metricsRetentionHours} exceeds recommended maximum ${constraints.maximumRetentionHours}`,
      code: 'RETENTION_TOO_LONG',
      severity: 'warning',
    });
  }

  // Validate phase count
  if (config.phases.length < constraints.requiredPhases.min) {
    errors.push({
      field: 'phases',
      message: `Phase count ${config.phases.length} is below minimum ${constraints.requiredPhases.min}`,
      code: 'INSUFFICIENT_PHASES',
      severity: 'error',
    });
  }

  if (config.phases.length > constraints.requiredPhases.max) {
    warnings.push({
      field: 'phases',
      message: `Phase count ${config.phases.length} exceeds recommended maximum ${constraints.requiredPhases.max}`,
      code: 'TOO_MANY_PHASES',
      severity: 'warning',
    });
  }

  // Validate phases
  const phaseValidation = validatePhaseProgression(config.phases);
  errors.push(...phaseValidation.errors);
  warnings.push(...phaseValidation.warnings);

  // Validate version format
  const versionRegex = /^\d+\.\d+\.\d+(-[a-zA-Z0-9]+)?$/;
  if (!versionRegex.test(config.stableVersion)) {
    warnings.push({
      field: 'stableVersion',
      message: `Stable version ${config.stableVersion} may not follow semantic versioning`,
      code: 'INVALID_VERSION_FORMAT',
      severity: 'warning',
    });
  }

  if (!versionRegex.test(config.canaryVersion)) {
    warnings.push({
      field: 'canaryVersion',
      message: `Canary version ${config.canaryVersion} may not follow semantic versioning`,
      code: 'INVALID_VERSION_FORMAT',
      severity: 'warning',
    });
  }

  // Check if versions are different
  if (config.stableVersion === config.canaryVersion) {
    errors.push({
      field: 'canaryVersion',
      message: `Canary version must be different from stable version`,
      code: 'IDENTICAL_VERSIONS',
      severity: 'error',
    });
  }

  return {
    isValid: errors.length === 0,
    value: {
      deploymentId: createDeploymentId(config.deploymentId),
      serviceName: config.serviceName,
      stableVersion: config.stableVersion,
      canaryVersion: config.canaryVersion,
      maxDeploymentTimeMs: config.maxDeploymentTimeMs,
      healthCheckIntervalMs: config.healthCheckIntervalMs,
      metricsRetentionHours: config.metricsRetentionHours,
      phases: phaseValidation.value,
    },
    errors,
    warnings,
  };
}

// ============================================================================
// Resource Constraint Validation
// ============================================================================

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
 * Validate resource constraints
 */
export function validateResourceConstraints(
  constraints: ResourceConstraints
): ConstraintValidationResult<ResourceConstraints> {
  const errors: ValidationError[] = [];
  const warnings: ValidationWarning[] = [];

  const validatedConstraints: ResourceConstraints = {};

  if (constraints.maxMemoryPerInstance !== undefined) {
    if (constraints.maxMemoryPerInstance <= 0 || constraints.maxMemoryPerInstance > 1024 * 1024) { // 1TB max
      errors.push({
        field: 'maxMemoryPerInstance',
        message: `Invalid max memory per instance: ${constraints.maxMemoryPerInstance}`,
        code: 'INVALID_MEMORY_LIMIT',
        severity: 'error',
      });
    } else {
      validatedConstraints.maxMemoryPerInstance = constraints.maxMemoryPerInstance;
    }
  }

  if (constraints.maxCPUPerInstance !== undefined) {
    if (constraints.maxCPUPerInstance <= 0 || constraints.maxCPUPerInstance > 100) {
      errors.push({
        field: 'maxCPUPerInstance',
        message: `Invalid max CPU per instance: ${constraints.maxCPUPerInstance}`,
        code: 'INVALID_CPU_LIMIT',
        severity: 'error',
      });
    } else {
      validatedConstraints.maxCPUPerInstance = constraints.maxCPUPerInstance;
    }
  }

  if (constraints.maxInstances !== undefined) {
    if (constraints.maxInstances <= 0 || constraints.maxInstances > 1000) {
      errors.push({
        field: 'maxInstances',
        message: `Invalid max instances: ${constraints.maxInstances}`,
        code: 'INVALID_INSTANCE_LIMIT',
        severity: 'error',
      });
    } else {
      validatedConstraints.maxInstances = constraints.maxInstances;
    }
  }

  if (constraints.maxTrafficPercentage !== undefined) {
    const trafficValidation = validateInitialTrafficPercentage(constraints.maxTrafficPercentage, {
      ...DEFAULT_TRAFFIC_CONSTRAINTS,
      maximumInitial: 100,
      maximumTotal: 100,
    });
    if (!trafficValidation.isValid) {
      errors.push(...trafficValidation.errors);
      warnings.push(...trafficValidation.warnings);
    } else {
      validatedConstraints.maxTrafficPercentage = trafficValidation.value;
    }
  }

  if (constraints.maxRollbackTime !== undefined) {
    if (constraints.maxRollbackTime <= 0 || constraints.maxRollbackTime > 3600000) { // 1 hour max
      errors.push({
        field: 'maxRollbackTime',
        message: `Invalid max rollback time: ${constraints.maxRollbackTime}`,
        code: 'INVALID_ROLLBACK_TIME',
        severity: 'error',
      });
    } else {
      validatedConstraints.maxRollbackTime = constraints.maxRollbackTime;
    }
  }

  return {
    isValid: errors.length === 0,
    value: validatedConstraints,
    errors,
    warnings,
  };
}

// ============================================================================
// Constraint Validation Utilities
// ============================================================================

/**
 * Validate multiple constraints and combine results
 */
export function validateMultipleConstraints<T extends Record<string, unknown>>(
  validators: Array<() => ConstraintValidationResult<unknown>>
): ConstraintValidationResult<T> {
  const allErrors: ValidationError[] = [];
  const allWarnings: ValidationWarning[] = [];
  const validatedValues: Record<string, unknown> = {};

  for (const validator of validators) {
    const result = validator();
    allErrors.push(...result.errors);
    allWarnings.push(...result.warnings);

    // Merge validated values (simplified approach)
    Object.assign(validatedValues, result.value);
  }

  return {
    isValid: allErrors.length === 0,
    value: validatedValues as T,
    errors: allErrors,
    warnings: allWarnings,
  };
}

/**
 * Create a constraint validator function
 */
export function createConstraintValidator<T>(
  validator: (value: unknown) => ConstraintValidationResult<T>
): (value: unknown) => ConstraintValidationResult<T> {
  return validator;
}

/**
 * Compose multiple constraint validators
 */
export function composeConstraintValidators<T>(
  ...validators: Array<(value: unknown) => ConstraintValidationResult<unknown>>
): (value: unknown) => ConstraintValidationResult<T> {
  return (value: unknown) => {
    const results = validators.map(validator => validator(value));
    return validateMultipleConstraints(() => results[0]) as ConstraintValidationResult<T>;
  };
}