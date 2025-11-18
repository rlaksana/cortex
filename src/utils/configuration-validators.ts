// EMERGENCY ROLLBACK: Utility type guard compatibility issues

/**
 * Configuration Runtime Validation and Type Guards
 *
 * Comprehensive runtime validation utilities for configuration objects to ensure
 * type safety without using `any`. This module provides type guards, validation
 * functions, and safe parsing utilities for all configuration types.
 *
 * @version 2.0.0
 * @since 2025
 */

import type { Dict, JSONObject, JSONValue } from '../types/index.js';
import { isJSONObject, isJSONValue } from '../types/index.js';

// ============================================================================
// Configuration Type Guards
// ============================================================================

/**
 * Type guard for Qdrant configuration objects
 */
export function isQdrantConfig(value: unknown): value is {
  host: string;
  port: number;
  apiKey?: string;
  timeout?: number;
  maxRetries?: number;
  collection?: string;
  vectorSize?: number;
  distance?: 'Cosine' | 'Euclidean' | 'Dot';
} {
  if (!isJSONObject(value)) {
    return false;
  }

  const obj = value as Record<string, unknown>;

  // Required fields
  if (typeof obj.host !== 'string' || typeof obj.port !== 'number') {
    return false;
  }

  // Optional fields with type checking
  if (obj.apiKey !== undefined && typeof obj.apiKey !== 'string') {
    return false;
  }

  if (obj.timeout !== undefined && typeof obj.timeout !== 'number') {
    return false;
  }

  if (obj.maxRetries !== undefined && typeof obj.maxRetries !== 'number') {
    return false;
  }

  if (obj.collection !== undefined && typeof obj.collection !== 'string') {
    return false;
  }

  if (obj.vectorSize !== undefined && typeof obj.vectorSize !== 'number') {
    return false;
  }

  if (
    obj.distance !== undefined &&
    !['Cosine', 'Euclidean', 'Dot'].includes(obj.distance as string)
  ) {
    return false;
  }

  return true;
}

/**
 * Type guard for database connection configurations
 */
export function isDatabaseConnectionConfig(value: unknown): value is {
  type: 'qdrant';
  config: {
    host: string;
    port: number;
    apiKey?: string;
    timeout?: number;
    maxRetries?: number;
    collection?: string;
    vectorSize?: number;
    distance?: 'Cosine' | 'Euclidean' | 'Dot';
  };
} {
  if (!isJSONObject(value)) {
    return false;
  }

  const obj = value as Record<string, unknown>;

  if (obj.type !== 'qdrant' || !isQdrantConfig(obj.config)) {
    return false;
  }

  return true;
}

/**
 * Type guard for filter rule values
 */
export function isFilterValue(
  value: unknown
): value is string | number | boolean | null | JSONValue {
  return isJSONValue(value);
}

/**
 * Type guard for transformation rule objects
 */
export function isTransformationRule(value: unknown): value is {
  name: string;
  type: 'field' | 'value' | 'structure';
  sourceField?: string;
  targetField?: string;
  transformation: string;
  parameters?: Dict<JSONValue>;
} {
  if (!isJSONObject(value)) {
    return false;
  }

  const obj = value as Record<string, unknown>;

  return (
    typeof obj.name === 'string' &&
    typeof obj.type === 'string' &&
    typeof obj.transformation === 'string' &&
    (obj.sourceField === undefined || typeof obj.sourceField === 'string') &&
    (obj.targetField === undefined || typeof obj.targetField === 'string') &&
    (obj.parameters === undefined || isJSONObject(obj.parameters))
  );
}

/**
 * Type guard for migration configuration objects
 */
export function isMigrationConfig(value: unknown): value is {
  mode: string;
  generateEmbeddings: 'always' | 'if-missing' | 'never';
  embeddingModel: string;
  batchSize: number;
  contentFields: string[];
  metadataFields: string[];
  filterRules: Array<{
    name: string;
    field: string;
    operator: string;
    value: string | number | boolean | null | JSONValue;
    negate?: boolean;
  }>;
  transformationRules: Array<{
    name: string;
    type: string;
    sourceField?: string;
    targetField?: string;
    transformation: string;
    parameters?: Dict<JSONValue>;
  }>;
} {
  if (!isJSONObject(value)) {
    return false;
  }

  const obj = value as Record<string, unknown>;

  // Check required fields
  if (
    typeof obj.mode !== 'string' ||
    !['always', 'if-missing', 'never'].includes(obj.generateEmbeddings as string) ||
    typeof obj.embeddingModel !== 'string' ||
    typeof obj.batchSize !== 'number' ||
    !Array.isArray(obj.contentFields) ||
    !Array.isArray(obj.metadataFields) ||
    !Array.isArray(obj.filterRules) ||
    !Array.isArray(obj.transformationRules)
  ) {
    return false;
  }

  // Validate transformation rules
  for (const rule of obj.transformationRules) {
    if (!isTransformationRule(rule)) {
      return false;
    }
  }

  return true;
}

/**
 * Type guard for validation result objects
 */
export function isValidationResult(value: unknown): value is {
  valid: boolean;
  errors: Array<{
    code: string;
    message: string;
    field?: string;
    category: string;
    severity: string;
    suggestion?: string;
    context?: Record<string, JSONValue>;
  }>;
  warnings: Array<{
    code: string;
    message: string;
    field?: string;
    category: string;
    severity: string;
    suggestion?: string;
    context?: Record<string, JSONValue>;
  }>;
  data?: {
    data: JSONValue;
    validatedAt: string;
    schemaVersion: string;
  };
  metadata: {
    validationTimeMs: number;
    validatorVersion: string;
    schemaVersion: string;
    validationMode: string;
  };
} {
  if (!isJSONObject(value)) {
    return false;
  }

  const obj = value as Record<string, unknown>;

  return (
    typeof obj.valid === 'boolean' &&
    Array.isArray(obj.errors) &&
    Array.isArray(obj.warnings) &&
    isJSONObject(obj.metadata)
  );
}

// ============================================================================
// Runtime Validation Functions
// ============================================================================

/**
 * Runtime validator with detailed error reporting
 */
export function validateConfig<T>(
  value: unknown,
  typeGuard: (value: unknown) => value is T,
  context?: string
): { success: true; data: T } | { success: false; error: string } {
  try {
    if (typeGuard(value)) {
      return { success: true, data: value };
    }

    return {
      success: false,
      error: `Invalid configuration${context ? ` in ${context}` : ''}: type guard failed`,
    };
  } catch (error) {
    return {
      success: false,
      error: `Configuration validation error${context ? ` in ${context}` : ''}: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

/**
 * Safe configuration parsing with fallback
 */
export function safeParseConfig<T>(
  value: unknown,
  typeGuard: (value: unknown) => value is T,
  fallback: T,
  context?: string
): T {
  const result = validateConfig(value, typeGuard, context);
  return result.success ? result.data : fallback;
}

/**
 * Type assertion with runtime check
 */
export function assertType<T>(
  value: unknown,
  typeGuard: (value: unknown) => value is T,
  message?: string
): asserts value is T {
  if (!typeGuard(value)) {
    throw new TypeError(message || `Type assertion failed: value does not match expected type`);
  }
}

// ============================================================================
// Configuration Builders
// ============================================================================

/**
 * Type-safe configuration builder for Qdrant
 */
export class QdrantConfigBuilder {
  private config: Partial<{
    host: string;
    port: number;
    apiKey: string;
    timeout: number;
    maxRetries: number;
    collection: string;
    vectorSize: number;
    distance: 'Cosine' | 'Euclidean' | 'Dot';
  }> = {};

  withHost(host: string): this {
    this.config.host = host;
    return this;
  }

  withPort(port: number): this {
    this.config.port = port;
    return this;
  }

  withApiKey(apiKey: string): this {
    this.config.apiKey = apiKey;
    return this;
  }

  withTimeout(timeout: number): this {
    this.config.timeout = timeout;
    return this;
  }

  withMaxRetries(maxRetries: number): this {
    this.config.maxRetries = maxRetries;
    return this;
  }

  withCollection(collection: string): this {
    this.config.collection = collection;
    return this;
  }

  withVectorSize(vectorSize: number): this {
    this.config.vectorSize = vectorSize;
    return this;
  }

  withDistance(distance: 'Cosine' | 'Euclidean' | 'Dot'): this {
    this.config.distance = distance;
    return this;
  }

  build(): { host: string; port: number } & Partial<{
    apiKey: string;
    timeout: number;
    maxRetries: number;
    collection: string;
    vectorSize: number;
    distance: 'Cosine' | 'Euclidean' | 'Dot';
  }> {
    if (!this.config.host || !this.config.port) {
      throw new Error('QdrantConfig requires host and port');
    }

    return {
      host: this.config.host,
      port: this.config.port,
      ...this.config,
    };
  }
}

/**
 * Type-safe configuration merger
 */
export function mergeConfigs<T extends JSONObject>(base: T, ...configs: Partial<T>[]): T {
  return configs.reduce((merged, config) => ({ ...merged, ...config }), { ...base });
}

/**
 * Deep configuration merger with type safety
 */
export function deepMergeConfigs<T extends JSONObject>(base: T, ...configs: Partial<T>[]): T {
  return configs.reduce((merged, config) => {
    const result = { ...merged } as T;

    for (const [key, value] of Object.entries(config)) {
      if (value === undefined) continue;

      const typedKey = key as Extract<keyof T, string>;
      if (isJSONObject(result[typedKey]) && isJSONObject(value)) {
        result[typedKey] = deepMergeConfigs(result[typedKey] as JSONObject, value as JSONObject) as T[Extract<keyof T, string>];
      } else {
        (result as any)[typedKey] = value;
      }
    }

    return result;
  }, { ...base });
}

// ============================================================================
// Environment Configuration Validators
// ============================================================================

/**
 * Validate environment-specific configuration
 */
export function isEnvironmentConfig(value: unknown): value is {
  development?: Dict<JSONValue>;
  staging?: Dict<JSONValue>;
  production?: Dict<JSONValue>;
  test?: Dict<JSONValue>;
} {
  if (!isJSONObject(value)) {
    return false;
  }

  const obj = value as Record<string, unknown>;

  // Check each environment if present
  const environments = ['development', 'staging', 'production', 'test'];
  for (const env of environments) {
    if (obj[env] !== undefined && !isJSONObject(obj[env])) {
      return false;
    }
  }

  return true;
}

/**
 * Validate production configuration
 */
export function isProductionConfig(value: unknown): value is {
  security: {
    corsOrigin: string[];
    rateLimitEnabled: boolean;
    rateLimitWindowMs: number;
    rateLimitMaxRequests: number;
    helmetEnabled: boolean;
    requireApiKey: boolean;
    maxRequestSizeMb: number;
    enableCompression: boolean;
  };
  health: {
    enabled: boolean;
    detailedEndpoints: boolean;
    metricsEndpoint: boolean;
    authenticationRequired: boolean;
    allowedIPs: string[];
  };
  shutdown: {
    timeout: number;
    forceTimeout: number;
    enableDrainMode: boolean;
    drainTimeout: number;
  };
  logging: {
    level: string;
    format: 'json' | 'text';
    structured: boolean;
    includeTimestamp: boolean;
    includeRequestId: boolean;
  };
  performance: {
    enableMetrics: boolean;
    enablePerformanceMonitoring: boolean;
    nodeOptions: string;
    maxOldSpaceSize: number;
    maxHeapSize: number;
  };
  monitoring: {
    enableSystemMetrics: boolean;
    enableHealthChecks: boolean;
    metricsInterval: number;
    healthCheckInterval: number;
  };
} {
  if (!isJSONObject(value)) {
    return false;
  }

  const obj = value as Record<string, unknown>;

  // Validate required top-level sections
  const requiredSections = [
    'security',
    'health',
    'shutdown',
    'logging',
    'performance',
    'monitoring',
  ];
  for (const section of requiredSections) {
    if (!isJSONObject(obj[section])) {
      return false;
    }
  }

  // Basic type checks for critical security settings
  const security = obj.security as Record<string, unknown>;
  if (!Array.isArray(security.corsOrigin) || typeof security.rateLimitEnabled !== 'boolean') {
    return false;
  }

  return true;
}

// ============================================================================
// Validation Error Types
// ============================================================================

/**
 * Configuration validation error with context
 */
export interface ConfigurationValidationError {
  field: string;
  message: string;
  code: string;
  context?: Dict<JSONValue>;
  severity: 'error' | 'warning' | 'info';
}

/**
 * Validation result with detailed errors
 */
export interface ConfigurationValidationResult {
  valid: boolean;
  errors: ConfigurationValidationError[];
  warnings: ConfigurationValidationError[];
  data?: unknown;
  metadata: {
    validatedAt: string;
    validatorVersion: string;
  };
}

// ============================================================================
// Validation Utilities
// ============================================================================

/**
 * Create a validation error
 */
export function createValidationError(
  field: string,
  message: string,
  code: string,
  severity: ConfigurationValidationError['severity'] = 'error',
  context?: Dict<JSONValue>
): ConfigurationValidationError {
  return {
    field,
    message,
    code,
    severity,
    context,
  };
}

/**
 * Create a successful validation result
 */
export function createValidationResult(
  data?: unknown,
  warnings: ConfigurationValidationError[] = []
): ConfigurationValidationResult {
  return {
    valid: true,
    errors: [],
    warnings,
    data,
    metadata: {
      validatedAt: new Date().toISOString(),
      validatorVersion: '2.0.0',
    },
  };
}

/**
 * Create a failed validation result
 */
export function createFailedValidationResult(
  errors: ConfigurationValidationError[],
  warnings: ConfigurationValidationError[] = []
): ConfigurationValidationResult {
  return {
    valid: false,
    errors,
    warnings,
    metadata: {
      validatedAt: new Date().toISOString(),
      validatorVersion: '2.0.0',
    },
  };
}

/**
 * Validate configuration with comprehensive error reporting
 */
export function validateConfigurationObject(
  config: unknown,
  validators: Array<{
    field: string;
    validate: (value: unknown) => ConfigurationValidationError | null;
  }>
): ConfigurationValidationResult {
  if (!isJSONObject(config)) {
    return createFailedValidationResult([
      createValidationError('root', 'Configuration must be an object', 'INVALID_TYPE'),
    ]);
  }

  const errors: ConfigurationValidationError[] = [];
  const warnings: ConfigurationValidationError[] = [];

  for (const validator of validators) {
    const value = (config as Record<string, unknown>)[validator.field];
    const result = validator.validate(value);

    if (result) {
      if (result.severity === 'error') {
        errors.push(result);
      } else {
        warnings.push(result);
      }
    }
  }

  return errors.length > 0
    ? createFailedValidationResult(errors, warnings)
    : createValidationResult(config, warnings);
}

// ============================================================================
// Basic Utility Type Guards (Missing Exports)
// ============================================================================

/**
 * Type guard for dictionary objects (string-keyed records)
 */
export function isDict(value: unknown): value is Record<string, unknown> {
  return isJSONObject(value);
}

/**
 * Type guard for valid port numbers
 */
export function isValidPort(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= 65535;
}

/**
 * Type guard for valid timeout values
 */
export function isValidTimeout(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0;
}

/**
 * Validate and normalize configuration object
 */
export function validateAndNormalizeConfig(
  config: unknown,
  schema?: Record<string, { type: string; required?: boolean; default?: unknown }>
): { valid: boolean; config: Record<string, unknown>; errors: string[] } {
  const errors: string[] = [];

  if (!isJSONObject(config)) {
    errors.push('Configuration must be a valid object');
    return { valid: false, config: {}, errors };
  }

  const normalized = { ...(config as Record<string, unknown>) };

  if (schema) {
    for (const [key, rule] of Object.entries(schema)) {
      if (rule.required && !(key in normalized)) {
        errors.push(`Required field '${key}' is missing`);
        continue;
      }

      if (!(key in normalized) && rule.default !== undefined) {
        normalized[key] = rule.default;
      }

      const value = normalized[key];
      switch (rule.type) {
        case 'string':
          if (value !== undefined && typeof value !== 'string') {
            errors.push(`Field '${key}' must be a string`);
          }
          break;
        case 'number':
          if (value !== undefined && typeof value !== 'number') {
            errors.push(`Field '${key}' must be a number`);
          }
          break;
        case 'boolean':
          if (value !== undefined && typeof value !== 'boolean') {
            errors.push(`Field '${key}' must be a boolean`);
          }
          break;
        case 'object':
          if (value !== undefined && !isJSONObject(value)) {
            errors.push(`Field '${key}' must be an object`);
          }
          break;
      }
    }
  }

  return {
    valid: errors.length === 0,
    config: normalized,
    errors,
  };
}
