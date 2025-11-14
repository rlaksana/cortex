/**
 * Configuration Validation Utilities
 *
 * Provides comprehensive validation utilities for configuration objects
 * with runtime type checking and detailed error reporting. This system
 * ensures type safety across all configuration management operations.
 *
 * @version 2.0.0 - Type Safety Implementation
 */

import { logger } from '@/utils/logger.js';

import type {
  DatabaseConnectionConfig,
  DataTransformationConfig,
  FilterRule,
  FilterValue,
  MigrationEnvironmentConfig,
  PerformanceConfig,
  ProgressTrackingConfig,
  SafetyConfig,
  TransformationRule,
  ValidationConfig,
} from './migration-config.js';
import {
  assertType,
  isDatabaseConnectionConfig,
  isFilterRule,
  isFilterValue,
  isMigrationConfig,
  isQdrantConfig,
  isTransformationRule,
  validateConfig,
} from '../schemas/type-guards.js';
import type {
  Config,
  Dict,
  JSONValue,
  ValidationResult as BaseValidationResult,
} from '../types/index.js';

// ============================================================================
// Configuration Validation Result Types
// ============================================================================

export interface ConfigurationValidationResult {
  valid: boolean;
  errors: ConfigurationValidationError[];
  warnings: ConfigurationValidationWarning[];
  validatedConfig?: MigrationEnvironmentConfig;
  metadata: {
    validationTimeMs: number;
    validatorVersion: string;
    configVersion: string;
    checkedSections: string[];
  };
}

export interface ConfigurationValidationError {
  code: string;
  message: string;
  section: string;
  field?: string;
  severity: 'error' | 'critical';
  suggestion?: string;
  context?: Record<string, JSONValue>;
}

export interface ConfigurationValidationWarning {
  code: string;
  message: string;
  section: string;
  field?: string;
  suggestion?: string;
  context?: Record<string, JSONValue>;
}

// ============================================================================
// Configuration Validator
// ============================================================================

export class ConfigurationValidator {
  private static readonly VERSION = '2.0.0';

  /**
   * Validate complete migration configuration
   */
  static validateMigrationConfig(
    config: unknown,
    options: {
      strict?: boolean;
      includeWarnings?: boolean;
      validateConnections?: boolean;
    } = {}
  ): ConfigurationValidationResult {
    const startTime = Date.now();
    const errors: ConfigurationValidationError[] = [];
    const warnings: ConfigurationValidationWarning[] = [];
    const checkedSections: string[] = [];

    try {
      // Validate basic structure
      if (!config || typeof config !== 'object') {
        errors.push({
          code: 'CONFIG_INVALID_STRUCTURE',
          message: 'Configuration must be a valid object',
          section: 'root',
          severity: 'critical',
          suggestion: 'Ensure configuration is a valid JSON object',
        });
        return this.createResult(errors, warnings, startTime, checkedSections);
      }

      const configObj = config as Record<string, unknown>;
      checkedSections.push('structure');

      // Validate mode
      if (!configObj.mode || typeof configObj.mode !== 'string') {
        errors.push({
          code: 'CONFIG_MISSING_MODE',
          message: 'Migration mode is required',
          section: 'mode',
          field: 'mode',
          severity: 'critical',
          suggestion: 'Specify migration mode: pg-to-qdrant, qdrant-to-pg, sync, validate, or cleanup',
        });
      } else {
        const validModes = ['pg-to-qdrant', 'qdrant-to-pg', 'sync', 'validate', 'cleanup'];
        if (!validModes.includes(configObj.mode)) {
          errors.push({
            code: 'CONFIG_INVALID_MODE',
            message: `Invalid migration mode: ${configObj.mode}`,
            section: 'mode',
            field: 'mode',
            severity: 'error',
            suggestion: `Use one of: ${validModes.join(', ')}`,
          });
        }
        checkedSections.push('mode');
      }

      // Validate data transformation config
      if (configObj.dataTransformation) {
        const dataValidation = this.validateDataTransformationConfig(configObj.dataTransformation);
        errors.push(...dataValidation.errors);
        warnings.push(...dataValidation.warnings);
        checkedSections.push('dataTransformation');
      }

      // Validate validation config
      if (configObj.validation) {
        const validationConfigResult = this.validateValidationConfig(configObj.validation);
        errors.push(...validationConfigResult.errors);
        warnings.push(...validationConfigResult.warnings);
        checkedSections.push('validation');
      }

      // Validate performance config
      if (configObj.performance) {
        const performanceValidation = this.validatePerformanceConfig(configObj.performance);
        errors.push(...performanceValidation.errors);
        warnings.push(...performanceValidation.warnings);
        checkedSections.push('performance');
      }

      // Validate safety config
      if (configObj.safety) {
        const safetyValidation = this.validateSafetyConfig(configObj.safety);
        errors.push(...safetyValidation.errors);
        warnings.push(...safetyValidation.warnings);
        checkedSections.push('safety');
      }

      // Validate database connections
      if (options.validateConnections) {
        if (configObj.source) {
          const sourceValidation = this.validateDatabaseConnection(configObj.source, 'source');
          errors.push(...sourceValidation.errors);
          warnings.push(...sourceValidation.warnings);
          checkedSections.push('source');
        }

        if (configObj.target) {
          const targetValidation = this.validateDatabaseConnection(configObj.target, 'target');
          errors.push(...targetValidation.errors);
          warnings.push(...targetValidation.warnings);
          checkedSections.push('target');
        }
      }

      // If no critical errors, validate the complete config structure
      const hasCriticalErrors = errors.some(e => e.severity === 'critical');
      if (!hasCriticalErrors) {
        const completeValidation = validateConfig(config, this.isCompleteMigrationConfig);
        if (!completeValidation.success) {
          errors.push({
            code: 'CONFIG_INVALID_COMPLETE',
            message: completeValidation.error,
            section: 'complete',
            severity: 'error',
            suggestion: 'Review overall configuration structure',
          });
        } else if (completeValidation.success) {
          checkedSections.push('complete');
        }
      }

      return this.createResult(errors, warnings, startTime, checkedSections, config as MigrationEnvironmentConfig);
    } catch (error) {
      logger.error({ error, config }, 'Configuration validation failed unexpectedly');

      errors.push({
        code: 'CONFIG_VALIDATION_ERROR',
        message: `Unexpected validation error: ${error instanceof Error ? error.message : String(error)}`,
        section: 'system',
        severity: 'critical',
        suggestion: 'Check configuration format and contact support if issue persists',
      });

      return this.createResult(errors, warnings, startTime, checkedSections);
    }
  }

  /**
   * Validate data transformation configuration
   */
  private static validateDataTransformationConfig(
    config: unknown
  ): { errors: ConfigurationValidationError[]; warnings: ConfigurationValidationWarning[] } {
    const errors: ConfigurationValidationError[] = [];
    const warnings: ConfigurationValidationWarning[] = [];

    if (!config || typeof config !== 'object') {
      errors.push({
        code: 'DATA_TRANSFORM_INVALID',
        message: 'Data transformation configuration must be an object',
        section: 'dataTransformation',
        severity: 'error',
        suggestion: 'Provide valid data transformation configuration',
      });
      return { errors, warnings };
    }

    const dtConfig = config as Record<string, unknown>;

    // Validate required fields
    if (typeof dtConfig.generateEmbeddings !== 'string' ||
        !['always', 'if-missing', 'never'].includes(dtConfig.generateEmbeddings)) {
      errors.push({
        code: 'DATA_TRANSFORM_INVALID_EMBEDDINGS',
        message: 'Invalid generateEmbeddings setting',
        section: 'dataTransformation',
        field: 'generateEmbeddings',
        severity: 'error',
        suggestion: 'Use one of: always, if-missing, never',
      });
    }

    if (typeof dtConfig.embeddingModel !== 'string') {
      errors.push({
        code: 'DATA_TRANSFORM_MISSING_MODEL',
        message: 'Embedding model is required',
        section: 'dataTransformation',
        field: 'embeddingModel',
        severity: 'error',
        suggestion: 'Specify a valid embedding model name',
      });
    }

    if (typeof dtConfig.batchSize !== 'number' || dtConfig.batchSize <= 0) {
      errors.push({
        code: 'DATA_TRANSFORM_INVALID_BATCH_SIZE',
        message: 'Batch size must be a positive number',
        section: 'dataTransformation',
        field: 'batchSize',
        severity: 'error',
        suggestion: 'Set batch size to a positive integer (recommended: 50-200)',
      });
    }

    // Validate arrays
    if (!Array.isArray(dtConfig.contentFields)) {
      errors.push({
        code: 'DATA_TRANSFORM_INVALID_CONTENT_FIELDS',
        message: 'Content fields must be an array',
        section: 'dataTransformation',
        field: 'contentFields',
        severity: 'error',
        suggestion: 'Provide an array of field names to use as content',
      });
    }

    if (!Array.isArray(dtConfig.metadataFields)) {
      errors.push({
        code: 'DATA_TRANSFORM_INVALID_METADATA_FIELDS',
        message: 'Metadata fields must be an array',
        section: 'dataTransformation',
        field: 'metadataFields',
        severity: 'error',
        suggestion: 'Provide an array of field names to include as metadata',
      });
    }

    // Validate filter rules
    if (dtConfig.filterRules && Array.isArray(dtConfig.filterRules)) {
      dtConfig.filterRules.forEach((rule, index) => {
        if (!isFilterRule(rule)) {
          errors.push({
            code: 'DATA_TRANSFORM_INVALID_FILTER_RULE',
            message: `Invalid filter rule at index ${index}`,
            section: 'dataTransformation',
            field: `filterRules[${index}]`,
            severity: 'error',
            suggestion: 'Ensure filter rules have valid structure',
          });
        }
      });
    }

    // Validate transformation rules
    if (dtConfig.transformationRules && Array.isArray(dtConfig.transformationRules)) {
      dtConfig.transformationRules.forEach((rule, index) => {
        if (!isTransformationRule(rule)) {
          errors.push({
            code: 'DATA_TRANSFORM_INVALID_TRANSFORMATION_RULE',
            message: `Invalid transformation rule at index ${index}`,
            section: 'dataTransformation',
            field: `transformationRules[${index}]`,
            severity: 'error',
            suggestion: 'Ensure transformation rules have valid structure',
          });
        }
      });
    }

    // Add warnings for potential issues
    if (dtConfig.batchSize && typeof dtConfig.batchSize === 'number' && dtConfig.batchSize > 500) {
      warnings.push({
        code: 'DATA_TRANSFORM_LARGE_BATCH_SIZE',
        message: 'Large batch size may impact performance',
        section: 'dataTransformation',
        field: 'batchSize',
        suggestion: 'Consider reducing batch size for better memory management',
      });
    }

    return { errors, warnings };
  }

  /**
   * Validate validation configuration
   */
  private static validateValidationConfig(
    config: unknown
  ): { errors: ConfigurationValidationError[]; warnings: ConfigurationValidationWarning[] } {
    const errors: ConfigurationValidationError[] = [];
    const warnings: ConfigurationValidationWarning[] = [];

    if (!config || typeof config !== 'object') {
      errors.push({
        code: 'VALIDATION_CONFIG_INVALID',
        message: 'Validation configuration must be an object',
        section: 'validation',
        severity: 'error',
        suggestion: 'Provide valid validation configuration',
      });
      return { errors, warnings };
    }

    const vConfig = config as Record<string, unknown>;

    // Validate boolean fields
    const booleanFields = ['enabled', 'checkSum', 'checkEmbeddings', 'checkMetadata'];
    booleanFields.forEach(field => {
      if (vConfig[field] !== undefined && typeof vConfig[field] !== 'boolean') {
        errors.push({
          code: 'VALIDATION_CONFIG_INVALID_BOOLEAN',
          message: `${field} must be a boolean value`,
          section: 'validation',
          field,
          severity: 'error',
          suggestion: `Set ${field} to true or false`,
        });
      }
    });

    // Validate level
    if (vConfig.level && typeof vConfig.level === 'string') {
      const validLevels = ['basic', 'comprehensive', 'exhaustive'];
      if (!validLevels.includes(vConfig.level)) {
        errors.push({
          code: 'VALIDATION_CONFIG_INVALID_LEVEL',
          message: `Invalid validation level: ${vConfig.level}`,
          section: 'validation',
          field: 'level',
          severity: 'error',
          suggestion: `Use one of: ${validLevels.join(', ')}`,
        });
      }
    }

    // Validate numeric fields
    const numericFields = ['sampleSize', 'timeout', 'toleranceThreshold'];
    numericFields.forEach(field => {
      if (vConfig[field] !== undefined && (typeof vConfig[field] !== 'number' || vConfig[field] < 0)) {
        errors.push({
          code: 'VALIDATION_CONFIG_INVALID_NUMBER',
          message: `${field} must be a non-negative number`,
          section: 'validation',
          field,
          severity: 'error',
          suggestion: `Set ${field} to a positive number`,
        });
      }
    });

    return { errors, warnings };
  }

  /**
   * Validate performance configuration
   */
  private static validatePerformanceConfig(
    config: unknown
  ): { errors: ConfigurationValidationError[]; warnings: ConfigurationValidationWarning[] } {
    const errors: ConfigurationValidationError[] = [];
    const warnings: ConfigurationValidationWarning[] = [];

    if (!config || typeof config !== 'object') {
      errors.push({
        code: 'PERFORMANCE_CONFIG_INVALID',
        message: 'Performance configuration must be an object',
        section: 'performance',
        severity: 'error',
        suggestion: 'Provide valid performance configuration',
      });
      return { errors, warnings };
    }

    const pConfig = config as Record<string, unknown>;

    // Validate numeric fields
    const numericFields = [
      'maxConcurrency', 'memoryLimitMB', 'rateLimitRPS',
      'chunkSize', 'prefetchSize', 'gcInterval'
    ];

    numericFields.forEach(field => {
      if (pConfig[field] !== undefined) {
        if (typeof pConfig[field] !== 'number' || pConfig[field] <= 0) {
          errors.push({
            code: 'PERFORMANCE_CONFIG_INVALID_NUMBER',
            message: `${field} must be a positive number`,
            section: 'performance',
            field,
            severity: 'error',
            suggestion: `Set ${field} to a positive integer`,
          });
        }
      }
    });

    // Add warnings for potentially problematic values
    if (pConfig.maxConcurrency && typeof pConfig.maxConcurrency === 'number' && pConfig.maxConcurrency > 20) {
      warnings.push({
        code: 'PERFORMANCE_CONFIG_HIGH_CONCURRENCY',
        message: 'High concurrency may impact system stability',
        section: 'performance',
        field: 'maxConcurrency',
        suggestion: 'Consider reducing concurrency for better stability',
      });
    }

    if (pConfig.memoryLimitMB && typeof pConfig.memoryLimitMB === 'number' && pConfig.memoryLimitMB > 2048) {
      warnings.push({
        code: 'PERFORMANCE_CONFIG_HIGH_MEMORY',
        message: 'High memory limit may cause system issues',
        section: 'performance',
        field: 'memoryLimitMB',
        suggestion: 'Monitor memory usage and consider reducing limit',
      });
    }

    return { errors, warnings };
  }

  /**
   * Validate safety configuration
   */
  private static validateSafetyConfig(
    config: unknown
  ): { errors: ConfigurationValidationError[]; warnings: ConfigurationValidationWarning[] } {
    const errors: ConfigurationValidationError[] = [];
    const warnings: ConfigurationValidationWarning[] = [];

    if (!config || typeof config !== 'object') {
      errors.push({
        code: 'SAFETY_CONFIG_INVALID',
        message: 'Safety configuration must be an object',
        section: 'safety',
        severity: 'error',
        suggestion: 'Provide valid safety configuration',
      });
      return { errors, warnings };
    }

    const sConfig = config as Record<string, unknown>;

    // Validate boolean fields
    const booleanFields = [
      'dryRun', 'preserveSource', 'requireConfirmation',
      'backupEnabled', 'resumeOnError', 'rollbackOnFailure'
    ];

    booleanFields.forEach(field => {
      if (sConfig[field] !== undefined && typeof sConfig[field] !== 'boolean') {
        errors.push({
          code: 'SAFETY_CONFIG_INVALID_BOOLEAN',
          message: `${field} must be a boolean value`,
          section: 'safety',
          field,
          severity: 'error',
          suggestion: `Set ${field} to true or false`,
        });
      }
    });

    // Validate numeric fields
    const numericFields = ['maxErrors', 'errorThreshold'];
    numericFields.forEach(field => {
      if (sConfig[field] !== undefined) {
        if (typeof sConfig[field] !== 'number' || sConfig[field] < 0) {
          errors.push({
            code: 'SAFETY_CONFIG_INVALID_NUMBER',
            message: `${field} must be a non-negative number`,
            section: 'safety',
            field,
            severity: 'error',
            suggestion: `Set ${field} to a non-negative number`,
          });
        }
      }
    });

    // Validate backup path
    if (sConfig.backupPath !== undefined && typeof sConfig.backupPath !== 'string') {
      errors.push({
        code: 'SAFETY_CONFIG_INVALID_BACKUP_PATH',
        message: 'Backup path must be a string',
        section: 'safety',
        field: 'backupPath',
        severity: 'error',
        suggestion: 'Provide a valid file path for backups',
      });
    }

    return { errors, warnings };
  }

  /**
   * Validate database connection configuration
   */
  private static validateDatabaseConnection(
    config: unknown,
    section: 'source' | 'target'
  ): { errors: ConfigurationValidationError[]; warnings: ConfigurationValidationWarning[] } {
    const errors: ConfigurationValidationError[] = [];
    const warnings: ConfigurationValidationWarning[] = [];

    if (!isDatabaseConnectionConfig(config)) {
      errors.push({
        code: 'DB_CONNECTION_INVALID',
        message: `Invalid ${section} database connection configuration`,
        section,
        severity: 'error',
        suggestion: 'Provide valid database connection configuration',
      });
      return { errors, warnings };
    }

    // Validate Qdrant-specific configuration
    if (!isQdrantConfig(config.config)) {
      errors.push({
        code: 'DB_QDRANT_CONFIG_INVALID',
        message: `Invalid Qdrant configuration for ${section}`,
        section,
        severity: 'error',
        suggestion: 'Ensure Qdrant configuration has required fields (host, port)',
      });
    } else {
      const qConfig = config.config;

      // Validate host
      if (!qConfig.host || typeof qConfig.host !== 'string') {
        errors.push({
          code: 'DB_QDRANT_MISSING_HOST',
          message: 'Qdrant host is required',
          section,
          field: 'config.host',
          severity: 'error',
          suggestion: 'Provide a valid Qdrant host address',
        });
      }

      // Validate port
      if (typeof qConfig.port !== 'number' || qConfig.port <= 0 || qConfig.port > 65535) {
        errors.push({
          code: 'DB_QDRANT_INVALID_PORT',
          message: 'Qdrant port must be a valid port number (1-65535)',
          section,
          field: 'config.port',
          severity: 'error',
          suggestion: 'Provide a valid Qdrant port number',
        });
      }

      // Add warnings for optional fields
      if (!qConfig.apiKey) {
        warnings.push({
          code: 'DB_QDRANT_MISSING_API_KEY',
          message: 'No API key provided for Qdrant connection',
          section,
          field: 'config.apiKey',
          suggestion: 'Consider providing an API key for secure connections',
        });
      }
    }

    return { errors, warnings };
  }

  /**
   * Type guard for complete migration configuration
   */
  public static isCompleteMigrationConfig(value: unknown): value is MigrationEnvironmentConfig {
    if (!value || typeof value !== 'object') {
      return false;
    }

    const config = value as Record<string, unknown>;

    return typeof config.mode === 'string' &&
           typeof config.dataTransformation === 'object' &&
           typeof config.validation === 'object' &&
           typeof config.performance === 'object' &&
           typeof config.safety === 'object' &&
           isDatabaseConnectionConfig(config.source) &&
           isDatabaseConnectionConfig(config.target);
  }

  /**
   * Create validation result
   */
  private static createResult(
    errors: ConfigurationValidationError[],
    warnings: ConfigurationValidationWarning[],
    startTime: number,
    checkedSections: string[],
    validatedConfig?: MigrationEnvironmentConfig
  ): ConfigurationValidationResult {
    return {
      valid: errors.length === 0,
      errors,
      warnings,
      validatedConfig,
      metadata: {
        validationTimeMs: Date.now() - startTime,
        validatorVersion: this.VERSION,
        configVersion: '2.0.0',
        checkedSections,
      },
    };
  }
}

// ============================================================================
// Export Utilities
// ============================================================================

/**
 * Quick validation function with simple boolean result
 */
export function isValidConfiguration(
  config: unknown,
  options?: { strict?: boolean }
): boolean {
  const result = ConfigurationValidator.validateMigrationConfig(config, options);
  return result.valid;
}

/**
 * Validate configuration with error throwing
 */
export function validateConfigurationOrThrow(
  config: unknown,
  options?: { strict?: boolean }
): MigrationEnvironmentConfig {
  const result = ConfigurationValidator.validateMigrationConfig(config, options);

  if (!result.valid) {
    const errorMessages = result.errors.map(e => `${e.section}: ${e.message}`).join('; ');
    throw new Error(`Configuration validation failed: ${errorMessages}`);
  }

  assertType(config, ConfigurationValidator.isCompleteMigrationConfig);
  return config as MigrationEnvironmentConfig;
}