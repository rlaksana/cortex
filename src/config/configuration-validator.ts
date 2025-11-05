/**
 * Configuration Validation System
 *
 * Provides comprehensive validation for all configuration objects in the MCP-Cortex system.
 * Ensures property name consistency, type safety, and value constraints.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import {
  HealthCheckConfigSchema,
  HttpClientConfigSchema,
  validateHealthCheckConfig,
  validateHttpClientConfig,
  isStandardHealthCheckConfig,
  isStandardHttpClientConfig,
  type StandardHealthCheckConfig,
  type StandardHttpClientConfig,
} from './configuration-migration.js';

// ============================================================================
// Validation Result Types
// ============================================================================

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
  metadata?: ValidationMetadata;
}

export interface ValidationError {
  code: string;
  message: string;
  path?: string;
  value?: any;
  constraint?: string;
}

export interface ValidationWarning {
  code: string;
  message: string;
  path?: string;
  value?: any;
  suggestion?: string;
}

export interface ValidationMetadata {
  validatedAt: Date;
  validatorVersion: string;
  migrationPerformed: boolean;
  deprecatedPropertiesUsed: string[];
}

export interface ConfigurationValidationOptions {
  strict?: boolean; // Fail on warnings
  allowDeprecated?: boolean; // Allow deprecated properties with warnings
  validateTypes?: boolean; // Perform runtime type checking
  normalizeValues?: boolean; // Normalize values (e.g., convert seconds to ms)
}

// ============================================================================
// Configuration Validator Class
// ============================================================================

export class ConfigurationValidator {
  private options: ConfigurationValidationOptions;

  constructor(options: ConfigurationValidationOptions = {}) {
    this.options = {
      strict: false,
      allowDeprecated: true,
      validateTypes: true,
      normalizeValues: true,
      ...options,
    };
  }

  /**
   * Validate health check configuration
   */
  validateHealthCheckConfig(config: any): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    const deprecatedProperties: string[] = [];
    let migrationPerformed = false;

    // Check for deprecated properties
    const deprecatedProps = ['timeout', 'retries', 'retryDelay'];
    for (const prop of deprecatedProps) {
      if (prop in config) {
        deprecatedProperties.push(prop);
        if (!this.options.allowDeprecated) {
          errors.push({
            code: 'DEPRECATED_PROPERTY',
            message: `Deprecated property '${prop}' is not allowed. Use '${prop}Ms' instead.`,
            path: prop,
            value: config[prop],
            constraint: 'Use standard property names with Ms suffix',
          });
        } else {
          warnings.push({
            code: 'DEPRECATED_PROPERTY',
            message: `Deprecated property '${prop}' should be replaced with '${prop}Ms'.`,
            path: prop,
            value: config[prop],
            suggestion: `Use '${prop}Ms' instead of '${prop}'`,
          });
        }
      }
    }

    // Check for missing required properties
    const requiredProps = ['timeoutMs', 'retryAttempts', 'retryDelayMs'];
    for (const prop of requiredProps) {
      if (!(prop in config)) {
        // Check if legacy property exists
        const legacyProp = prop.replace('Ms', '');
        if (legacyProp in config) {
          migrationPerformed = true;
          warnings.push({
            code: 'LEGACY_PROPERTY_AUTO_MIGRATED',
            message: `Legacy property '${legacyProp}' was automatically migrated to '${prop}'.`,
            path: legacyProp,
            value: config[legacyProp],
            suggestion: `Update configuration to use '${prop}' directly`,
          });
        } else {
          errors.push({
            code: 'MISSING_REQUIRED_PROPERTY',
            message: `Required property '${prop}' is missing.`,
            path: prop,
            constraint: 'Property is required',
          });
        }
      }
    }

    // Type validation
    if (this.options.validateTypes) {
      this.validateTypes(config, errors, warnings);
    }

    // Value constraints validation
    this.validateValueConstraints(config, errors, warnings);

    // If this is already a standard config, validate with schema
    if (isStandardHealthCheckConfig(config)) {
      const schemaValidation = validateHealthCheckConfig(config);
      if (!schemaValidation.valid) {
        schemaValidation.errors.forEach((error) => {
          errors.push({
            code: 'SCHEMA_VALIDATION_ERROR',
            message: error,
            constraint: 'Zod schema validation',
          });
        });
      }
    }

    return {
      valid: errors.length === 0 && (!this.options.strict || warnings.length === 0),
      errors,
      warnings,
      metadata: {
        validatedAt: new Date(),
        validatorVersion: '2.0.0',
        migrationPerformed,
        deprecatedPropertiesUsed: deprecatedProperties,
      },
    };
  }

  /**
   * Validate HTTP client configuration
   */
  validateHttpClientConfig(config: any): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    const deprecatedProperties: string[] = [];
    let migrationPerformed = false;

    // Check for deprecated properties
    const deprecatedProps = ['timeout', 'retries', 'retryDelay'];
    for (const prop of deprecatedProps) {
      if (prop in config) {
        deprecatedProperties.push(prop);
        if (!this.options.allowDeprecated) {
          errors.push({
            code: 'DEPRECATED_PROPERTY',
            message: `Deprecated property '${prop}' is not allowed. Use '${prop}Ms' instead.`,
            path: prop,
            value: config[prop],
            constraint: 'Use standard property names with Ms suffix',
          });
        } else {
          warnings.push({
            code: 'DEPRECATED_PROPERTY',
            message: `Deprecated property '${prop}' should be replaced with '${prop}Ms'.`,
            path: prop,
            value: config[prop],
            suggestion: `Use '${prop}Ms' instead of '${prop}'`,
          });
        }
      }
    }

    // Check for missing required properties
    const requiredProps = ['timeoutMs', 'retryAttempts', 'retryDelayMs'];
    for (const prop of requiredProps) {
      if (!(prop in config)) {
        // Check if legacy property exists
        const legacyProp = prop.replace('Ms', '');
        if (legacyProp in config) {
          migrationPerformed = true;
          warnings.push({
            code: 'LEGACY_PROPERTY_AUTO_MIGRATED',
            message: `Legacy property '${legacyProp}' was automatically migrated to '${prop}'.`,
            path: legacyProp,
            value: config[legacyProp],
            suggestion: `Update configuration to use '${prop}' directly`,
          });
        } else {
          errors.push({
            code: 'MISSING_REQUIRED_PROPERTY',
            message: `Required property '${prop}' is missing.`,
            path: prop,
            constraint: 'Property is required',
          });
        }
      }
    }

    // Type validation
    if (this.options.validateTypes) {
      this.validateTypes(config, errors, warnings);
    }

    // Value constraints validation
    this.validateValueConstraints(config, errors, warnings);

    // If this is already a standard config, validate with schema
    if (isStandardHttpClientConfig(config)) {
      const schemaValidation = validateHttpClientConfig(config);
      if (!schemaValidation.valid) {
        schemaValidation.errors.forEach((error) => {
          errors.push({
            code: 'SCHEMA_VALIDATION_ERROR',
            message: error,
            constraint: 'Zod schema validation',
          });
        });
      }
    }

    return {
      valid: errors.length === 0 && (!this.options.strict || warnings.length === 0),
      errors,
      warnings,
      metadata: {
        validatedAt: new Date(),
        validatorVersion: '2.0.0',
        migrationPerformed,
        deprecatedPropertiesUsed: deprecatedProperties,
      },
    };
  }

  /**
   * Validate any configuration object
   */
  validateConfiguration(
    config: any,
    type?: 'health-check' | 'http-client' | 'auto'
  ): ValidationResult {
    if (type === 'auto' || !type) {
      // Auto-detect configuration type
      if (this.isHealthCheckConfig(config)) {
        type = 'health-check';
      } else if (this.isHttpClientConfig(config)) {
        type = 'http-client';
      } else {
        return {
          valid: false,
          errors: [
            {
              code: 'UNKNOWN_CONFIGURATION_TYPE',
              message: 'Cannot determine configuration type. Specify type explicitly.',
              constraint: 'Type must be "health-check" or "http-client"',
            },
          ],
          warnings: [],
        };
      }
    }

    switch (type) {
      case 'health-check':
        return this.validateHealthCheckConfig(config);
      case 'http-client':
        return this.validateHttpClientConfig(config);
      default:
        return {
          valid: false,
          errors: [
            {
              code: 'UNSUPPORTED_CONFIGURATION_TYPE',
              message: `Unsupported configuration type: ${type}`,
              constraint: 'Supported types: "health-check", "http-client"',
            },
          ],
          warnings: [],
        };
    }
  }

  /**
   * Validate multiple configuration objects
   */
  validateMultipleConfigurations(configs: Array<{ config: any; type?: string; name?: string }>): {
    [name: string]: ValidationResult;
  } {
    const results: { [name: string]: ValidationResult } = {};

    for (const { config, type, name = 'unnamed' } of configs) {
      results[name] = this.validateConfiguration(config, type as any);
    }

    return results;
  }

  // ============================================================================
  // Private Helper Methods
  // ============================================================================

  private validateTypes(
    config: any,
    errors: ValidationError[],
    warnings: ValidationWarning[]
  ): void {
    // Validate timeout properties are numbers
    const timeoutProps = ['timeout', 'timeoutMs'];
    for (const prop of timeoutProps) {
      if (prop in config && typeof config[prop] !== 'number') {
        errors.push({
          code: 'INVALID_TYPE',
          message: `Property '${prop}' must be a number, got ${typeof config[prop]}.`,
          path: prop,
          value: config[prop],
          constraint: 'Must be a number',
        });
      }
    }

    // Validate retry properties are numbers
    const retryProps = ['retries', 'retryAttempts', 'retryDelay', 'retryDelayMs'];
    for (const prop of retryProps) {
      if (prop in config && typeof config[prop] !== 'number') {
        errors.push({
          code: 'INVALID_TYPE',
          message: `Property '${prop}' must be a number, got ${typeof config[prop]}.`,
          path: prop,
          value: config[prop],
          constraint: 'Must be a number',
        });
      }
    }

    // Validate headers property
    if ('headers' in config && config.headers !== null && typeof config.headers !== 'object') {
      errors.push({
        code: 'INVALID_TYPE',
        message: `Property 'headers' must be an object, got ${typeof config.headers}.`,
        path: 'headers',
        value: config.headers,
        constraint: 'Must be an object',
      });
    }
  }

  private validateValueConstraints(
    config: any,
    errors: ValidationError[],
    warnings: ValidationWarning[]
  ): void {
    // Validate timeout values are reasonable
    const timeoutProps = ['timeout', 'timeoutMs'];
    for (const prop of timeoutProps) {
      if (prop in config) {
        const value = config[prop];
        if (value < 0) {
          errors.push({
            code: 'INVALID_VALUE',
            message: `Property '${prop}' must be non-negative, got ${value}.`,
            path: prop,
            value: value,
            constraint: 'Must be >= 0',
          });
        } else if (value > 300000) {
          warnings.push({
            code: 'HIGH_TIMEOUT_VALUE',
            message: `Property '${prop}' has a very high value (${value}ms). Consider reducing it.`,
            path: prop,
            value: value,
            suggestion: 'Consider using a timeout of 30 seconds or less',
          });
        }
      }
    }

    // Validate retry attempt values
    const retryAttemptProps = ['retries', 'retryAttempts'];
    for (const prop of retryAttemptProps) {
      if (prop in config) {
        const value = config[prop];
        if (value < 0) {
          errors.push({
            code: 'INVALID_VALUE',
            message: `Property '${prop}' must be non-negative, got ${value}.`,
            path: prop,
            value: value,
            constraint: 'Must be >= 0',
          });
        } else if (value > 10) {
          warnings.push({
            code: 'HIGH_RETRY_COUNT',
            message: `Property '${prop}' has a high value (${value}). Consider reducing it to avoid long retry chains.`,
            path: prop,
            value: value,
            suggestion: 'Consider using 3-5 retries or less',
          });
        }
      }
    }

    // Validate retry delay values
    const retryDelayProps = ['retryDelay', 'retryDelayMs'];
    for (const prop of retryDelayProps) {
      if (prop in config) {
        const value = config[prop];
        if (value < 0) {
          errors.push({
            code: 'INVALID_VALUE',
            message: `Property '${prop}' must be non-negative, got ${value}.`,
            path: prop,
            value: value,
            constraint: 'Must be >= 0',
          });
        } else if (value > 60000) {
          warnings.push({
            code: 'HIGH_RETRY_DELAY',
            message: `Property '${prop}' has a high value (${value}ms). Consider reducing it.`,
            path: prop,
            value: value,
            suggestion: 'Consider using a retry delay of 10 seconds or less',
          });
        }
      }
    }
  }

  private isHealthCheckConfig(config: any): boolean {
    const healthCheckProps = [
      'enabled',
      'intervalMs',
      'timeoutMs',
      'failureThreshold',
      'successThreshold',
      'retryAttempts',
      'retryDelayMs',
      'interval',
      'timeout',
      'retries',
      'retryDelay',
    ];

    return healthCheckProps.some((prop) => prop in config);
  }

  private isHttpClientConfig(config: any): boolean {
    const httpClientProps = [
      'timeoutMs',
      'retryAttempts',
      'retryDelayMs',
      'timeout',
      'retries',
      'retryDelay',
      'headers',
    ];

    return httpClientProps.some((prop) => prop in config);
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Create a configuration validator with default options
 */
export function createConfigurationValidator(
  options?: ConfigurationValidationOptions
): ConfigurationValidator {
  return new ConfigurationValidator(options);
}

/**
 * Validate configuration with strict settings
 */
export function validateConfigurationStrict(
  config: any,
  type?: 'health-check' | 'http-client' | 'auto'
): ValidationResult {
  const validator = new ConfigurationValidator({ strict: true });
  return validator.validateConfiguration(config, type);
}

/**
 * Validate configuration with permissive settings (allows deprecated properties)
 */
export function validateConfigurationPermissive(
  config: any,
  type?: 'health-check' | 'http-client' | 'auto'
): ValidationResult {
  const validator = new ConfigurationValidator({ strict: false, allowDeprecated: true });
  return validator.validateConfiguration(config, type);
}

/**
 * Quick validation check (returns boolean)
 */
export function isValidConfiguration(
  config: any,
  type?: 'health-check' | 'http-client' | 'auto'
): boolean {
  const result = validateConfigurationPermissive(config, type);
  return result.valid;
}

// ============================================================================
// Global Validator Instance
// ============================================================================

/**
 * Default configuration validator instance
 */
export const defaultConfigurationValidator = new ConfigurationValidator();

// Export default validation methods for convenience
export const validateHealthCheckConfiguration =
  defaultConfigurationValidator.validateHealthCheckConfig.bind(defaultConfigurationValidator);
export const validateHttpClientConfiguration =
  defaultConfigurationValidator.validateHttpClientConfig.bind(defaultConfigurationValidator);
export const validateAnyConfiguration = defaultConfigurationValidator.validateConfiguration.bind(
  defaultConfigurationValidator
);
